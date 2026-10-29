"""Archive format scanner.

Detects zip slip / path traversal, recursive archives,
and cross-references torch.load() calls to files within the archive.
"""

import io
import os
import zipfile
import tarfile
import gzip
import bz2
import lzma
import ntpath
import posixpath
import stat
from typing import Optional

ARCHIVE_MAGICS = {
    b"\x50\x4b\x03\x04": "zip",
    b"\x50\x4b\x05\x06": "zip_eocd",
    b"\x50\x4b\x07\x08": "zip_spanned",
    b"\x1f\x8b": "gzip",
    b"\x42\x5a\x68": "bz2",
    b"\xfd\x37\x7a\x58\x5a\x00": "xz",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x75\x73\x74\x61\x72": "tar_ustar",
}

SUSPICIOUS_EXTENSIONS = {".pickle", ".pkl", ".joblib", ".dill", ".py", ".exe", ".so", ".dll"}
MAX_ARCHIVE_DEPTH = 3
MAX_EXTRACT_SIZE = 64 * 1024 * 1024
MAX_ARCHIVE_EXPANSION = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000
TORCH_LOAD_PATTERNS = [
    b"torch.load", b"torch.save", b"torch.jit.load",
    b"pickle.load", b"pickle.Unpickler", b"joblib.load",
]


def scan_archive(data: bytes, max_depth: int = MAX_ARCHIVE_DEPTH) -> list[dict]:
    findings = []

    if len(data) < 4:
        findings.append({"issue": "file_too_small", "severity": "high", "description": "File too small to contain valid archive"})
        return findings

    archive_type = _detect_archive_type(data)
    if archive_type is None:
        findings.append({"issue": "unknown_archive_format", "severity": "low", "description": "Could not determine archive format"})
        return findings

    if archive_type == "zip":
        findings.extend(_scan_zip(data, max_depth))
    elif archive_type == "gzip":
        findings.extend(_scan_gzip(data, max_depth))
    elif archive_type == "bz2" or archive_type == "xz":
        findings.extend(_scan_compressed(data, archive_type, max_depth))
    elif archive_type == "tar_ustar" or archive_type == "tar_gnu":
        findings.extend(_scan_tar(data, max_depth))
    elif archive_type == "7z":
        findings.append({"issue": "7z_format_detected", "severity": "medium", "description": "7z archives not fully supported — basic heuristic scan only"})
        findings.extend(_scan_raw_heuristics(data))
    else:
        findings.append({"issue": "unscanned_format", "severity": "low", "description": f"Archive format '{archive_type}' not deeply scanned"})

    return findings


def _detect_archive_type(data: bytes) -> Optional[str]:
    for magic, fmt in ARCHIVE_MAGICS.items():
        if data[:len(magic)] == magic:
            return fmt
    if data[0:2] == b"\x1f\x8b":
        return "gzip"
    try:
        if data.decode("ascii", errors="replace").startswith("7z"):
            return "7z"
    except Exception:
        pass
    return None


def _scan_zip(data: bytes, max_depth: int) -> list[dict]:
    findings = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                findings.append({"issue": "archive_member_limit", "severity": "high", "description": f"Archive has {len(infos)} entries; scan limit is {MAX_ARCHIVE_MEMBERS}"})
            expanded = 0
            for info in infos[:MAX_ARCHIVE_MEMBERS]:
                filename = info.filename
                if not isinstance(filename, str):
                    filename = filename.decode("utf-8", errors="replace")

                if _check_path_traversal(filename):
                    findings.append({"issue": "zip_slip_path_traversal", "severity": "critical", "description": f"Path traversal in archive entry: {filename}"})

                if _is_absolute_path(filename):
                    findings.append({"issue": "zip_slip_absolute_path", "severity": "critical", "description": f"Absolute path in archive entry: {filename}"})

                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    findings.append({"issue": "archive_symlink", "severity": "high", "description": f"Archive contains symlink entry: {filename}"})

                if info.compress_type == zipfile.ZIP_DEFLATED:
                    ratio = (info.file_size / max(info.compress_size, 1))
                    if ratio > 100:
                        findings.append({"issue": "high_compression_ratio", "severity": "medium", "description": f"Entry '{filename}' has extreme compression ratio {ratio:.0f}:1 (zip bomb indicator)"})

                if info.file_size > MAX_EXTRACT_SIZE:
                    findings.append({"issue": "oversized_entry", "severity": "high", "description": f"Entry '{filename}' has uncompressed size {info.file_size}"})
                    continue
                expanded += info.file_size
                if expanded > MAX_ARCHIVE_EXPANSION:
                    findings.append({"issue": "archive_expansion_limit", "severity": "high", "description": f"Expanded content exceeds the {MAX_ARCHIVE_EXPANSION}-byte scan budget"})
                    break

                ext = os.path.splitext(filename)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    severity = "medium" if ext in (".pickle", ".pkl", ".joblib", ".dill") else "high"
                    findings.append({"issue": "suspicious_archive_entry", "severity": severity, "description": f"Archive contains '{filename}' — inspect nested artifact"})

                if ext in (".pickle", ".pkl", ".dill", ".joblib") and info.file_size <= MAX_EXTRACT_SIZE:
                    try:
                        findings.extend(_scan_pickle_entry(filename, zf.read(info.filename)))
                    except Exception as exc:
                        findings.append({"issue": "nested_pickle_scan_error", "severity": "medium", "description": f"Could not inspect nested pickle '{filename}': {exc}"})

                if max_depth > 0:
                    try:
                        entry_data = zf.read(info.filename)
                        if _detect_archive_type(entry_data):
                            nested = scan_archive(entry_data, max_depth - 1)
                            for nf in nested:
                                nf["description"] = f"nested in '{filename}': {nf['description']}"
                            findings.extend(nested)
                    except Exception:
                        pass

            torch_refs = _find_torch_load_references(data)
            findings.extend(torch_refs)

    except zipfile.BadZipFile as e:
        findings.append({"issue": "corrupt_zip", "severity": "medium", "description": f"Corrupt ZIP archive: {e}"})
    except Exception as e:
        findings.append({"issue": "zip_scan_error", "severity": "medium", "description": f"Error scanning ZIP: {e}"})

    return findings


def _scan_tar(data: bytes, max_depth: int) -> list[dict]:
    findings = []

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            expanded = 0
            for index, member in enumerate(tf):
                if index >= MAX_ARCHIVE_MEMBERS:
                    findings.append({"issue": "archive_member_limit", "severity": "high", "description": f"Archive member count exceeds {MAX_ARCHIVE_MEMBERS}"})
                    break
                filename = member.name

                if _check_path_traversal(filename):
                    findings.append({"issue": "tar_slip_path_traversal", "severity": "critical", "description": f"Path traversal in tar entry: {filename}"})

                if filename.startswith("/"):
                    findings.append({"issue": "tar_absolute_path", "severity": "critical", "description": f"Absolute path in tar entry: {filename}"})

                if member.size > MAX_EXTRACT_SIZE:
                    findings.append({"issue": "oversized_tar_entry", "severity": "high", "description": f"Tar entry '{filename}' has size {member.size}"})
                    continue
                expanded += member.size
                if expanded > MAX_ARCHIVE_EXPANSION:
                    findings.append({"issue": "archive_expansion_limit", "severity": "high", "description": f"Expanded content exceeds the {MAX_ARCHIVE_EXPANSION}-byte scan budget"})
                    break

                ext = os.path.splitext(filename)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    severity = "medium" if ext in (".pickle", ".pkl", ".joblib", ".dill") else "high"
                    findings.append({"issue": "suspicious_tar_entry", "severity": severity, "description": f"Tar contains '{filename}'"})

                if ext in (".pickle", ".pkl", ".dill", ".joblib") and member.isfile():
                    fobj = tf.extractfile(member)
                    if fobj:
                        findings.extend(_scan_pickle_entry(filename, fobj.read(MAX_EXTRACT_SIZE + 1)))

                if member.issym() or member.islnk():
                    findings.append({"issue": "archive_link", "severity": "high", "description": f"Archive contains link entry: {filename}"})

                if max_depth > 0 and member.isfile() and member.size <= MAX_EXTRACT_SIZE:
                    try:
                        fobj = tf.extractfile(member)
                        if fobj:
                            entry_data = fobj.read()
                            if _detect_archive_type(entry_data):
                                nested = scan_archive(entry_data, max_depth - 1)
                                for nf in nested:
                                    nf["description"] = f"nested in '{filename}': {nf['description']}"
                                findings.extend(nested)
                    except Exception:
                        pass
    except tarfile.TarError as e:
        findings.append({"issue": "corrupt_tar", "severity": "medium", "description": f"Corrupt tar archive: {e}"})

    torch_refs = _find_torch_load_references(data)
    findings.extend(torch_refs)

    return findings


def _scan_gzip(data: bytes, max_depth: int) -> list[dict]:
    findings = []

    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            decompressed = stream.read(MAX_ARCHIVE_EXPANSION + 1)
        if len(decompressed) > MAX_ARCHIVE_EXPANSION:
            return [{"issue": "archive_expansion_limit", "severity": "high", "description": f"Gzip content exceeds the {MAX_ARCHIVE_EXPANSION}-byte scan budget"}]
        if max_depth > 0:
            nested_type = _detect_archive_type(decompressed)
            if nested_type:
                nested = scan_archive(decompressed, max_depth - 1)
                for nf in nested:
                    nf["description"] = f"nested in gzip: {nf['description']}"
                findings.extend(nested)
            else:
                torch_refs = _find_torch_load_references(decompressed)
                findings.extend(torch_refs)
    except Exception as e:
        findings.append({"issue": "corrupt_gzip", "severity": "medium", "description": f"Corrupt gzip: {e}"})

    return findings


def _scan_compressed(data: bytes, archive_type: str, max_depth: int) -> list[dict]:
    try:
        decompressor = bz2.BZ2Decompressor() if archive_type == "bz2" else lzma.LZMADecompressor()
        decompressed = decompressor.decompress(data, max_length=MAX_ARCHIVE_EXPANSION + 1)
        if len(decompressed) > MAX_ARCHIVE_EXPANSION:
            return [{"issue": "archive_expansion_limit", "severity": "high", "description": f"Expanded content exceeds the {MAX_ARCHIVE_EXPANSION}-byte scan budget"}]
        nested_type = _detect_archive_type(decompressed)
        if nested_type and max_depth > 0:
            return scan_archive(decompressed, max_depth - 1)
        return _find_torch_load_references(decompressed)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        return [{"issue": "corrupt_compressed_file", "severity": "medium", "description": f"Could not inspect compressed content: {exc}"}]


def _scan_raw_heuristics(data: bytes) -> list[dict]:
    findings = []
    entries = data.split(b"\x00")
    for entry in entries:
        try:
            name = entry.decode("utf-8", errors="replace")
            if _check_path_traversal(name):
                findings.append({"issue": "path_traversal_raw", "severity": "critical", "description": f"Path traversal in raw archive scan: {name}"})
        except Exception:
            pass
    return findings


def _check_path_traversal(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    decoded = normalized.replace("%2e", ".").replace("%2E", ".").replace("%2f", "/").replace("%2F", "/")
    parts = posixpath.normpath(decoded).split("/")
    return ".." in parts or _is_absolute_path(decoded)


def _scan_pickle_entry(filename: str, payload: bytes) -> list[dict]:
    if len(payload) > MAX_EXTRACT_SIZE:
        return [{"issue": "nested_pickle_size_limit", "severity": "low", "description": f"Nested pickle '{filename}' exceeds the scan limit"}]
    from model_harrier.scan.pickles import verify_pickle_bytes

    result = verify_pickle_bytes(payload)
    verdict = result.consensus.value if result.consensus else result.aieye_result.value
    findings = [{"issue": "nested_pickle_analysis", "severity": verdict, "description": f"{filename}: {reason}"} for reason in result.reasoning]
    if not findings:
        findings.append({"issue": "nested_pickle_analysis", "severity": "info", "description": f"{filename}: pickle opcodes analyzed; verdict {verdict}"})
    return findings


def _is_absolute_path(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    return normalized.startswith("/") or bool(ntpath.splitdrive(filename)[0])


def _find_torch_load_references(data: bytes) -> list[dict]:
    findings = []
    for pattern in TORCH_LOAD_PATTERNS:
        idx = data.find(pattern)
        if idx >= 0:
            context_start = max(0, idx - 60)
            context_end = min(len(data), idx + len(pattern) + 60)
            context = data[context_start:context_end]
            try:
                context_str = context.decode("utf-8", errors="replace")
            except Exception:
                context_str = repr(context)
            findings.append({"issue": "torch_load_in_archive", "severity": "high", "description": f"torch.load() reference found in archive content: ...{context_str}..."})
            break
    return findings
