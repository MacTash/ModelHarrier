"""ONNX format scanner.

Detects custom operators (potential code execution), external data file
references with path traversal, tensor size violations, and file tampering.
"""



MAX_OPSET_VERSION = 25
MAX_NODE_COUNT = 1_000_000
MAX_INITIALIZER_SIZE = 100 * 1024 * 1024 * 1024

SUSPICIOUS_OP_DOMAINS = {"com.microsoft.custom", "com.github.pytorch.custom", "test.ai.onnx"}

PATH_TRAVERSAL_PATTERNS = ["../", "..\\", "%2e%2e", "....//", "/etc/", "C:\\"]


def scan_onnx(data: bytes) -> list[dict]:
    findings = []
    if len(data) < 16:
        findings.append({"issue": "file_too_small", "severity": "high", "description": "File too small to contain valid ONNX protobuf"})
        return findings

    if data[0:2] != b"\x08\x08" and data[0:2] != b"\x08\x01":
        findings.append({"issue": "not_onnx_format", "severity": "medium", "description": "File does not appear to be a valid ONNX protobuf (missing expected field markers)"})

    try:
        import onnx
    except ImportError:
        findings.append({"issue": "onnx_not_installed", "severity": "low", "description": "onnx package not installed — using raw byte heuristics only"})
        _scan_raw_heuristics(data, findings)
        return findings

    try:
        model = onnx.load_from_bytes(data)
    except Exception as e:
        findings.append({"issue": "onnx_parse_error", "severity": "high", "description": f"Failed to parse ONNX model: {e}"})
        return findings

    graph = model.graph if hasattr(model, "graph") else None
    if graph is None:
        findings.append({"issue": "missing_graph", "severity": "high", "description": "ONNX model has no graph definition"})
        return findings

    opset_imports = model.opset_import if hasattr(model, "opset_import") else []
    for opset in opset_imports:
        version = getattr(opset, "version", 0)
        if version > MAX_OPSET_VERSION:
            findings.append({"issue": "high_opset_version", "severity": "medium", "description": f"Opset version {version} exceeds known maximum {MAX_OPSET_VERSION}"})

    node_count = len(graph.node) if hasattr(graph, "node") else 0
    if node_count > MAX_NODE_COUNT:
        findings.append({"issue": "excessive_nodes", "severity": "medium", "description": f"Graph has {node_count} nodes (max {MAX_NODE_COUNT})"})

    for i, node in enumerate(graph.node if hasattr(graph, "node") else []):
        domain = getattr(node, "domain", "")
        if domain in SUSPICIOUS_OP_DOMAINS:
            findings.append({"issue": "custom_operator_domain", "severity": "critical", "description": f"Node {i} uses custom domain '{domain}' — potential code execution risk"})
        if domain and domain not in ("", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "com.microsoft", "org.pytorch"):
            findings.append({"issue": "unusual_operator_domain", "severity": "high", "description": f"Node {i} uses unusual operator domain '{domain}'"})

        for attr in getattr(node, "attribute", []):
            if hasattr(attr, "ref_attr_name") and attr.ref_attr_name:
                pass
            if attr.type == 4:
                sub_bytes = getattr(attr, "t", None)
                if sub_bytes and len(sub_bytes) > MAX_INITIALIZER_SIZE:
                    findings.append({"issue": "oversized_tensor_attr", "severity": "high", "description": f"Node {i} attribute has tensor of {len(sub_bytes)} bytes"})

    initializers = graph.initializer if hasattr(graph, "initializer") else []
    for init in initializers:
        dims = list(init.dims) if hasattr(init, "dims") else []
        for d in dims:
            if d <= 0:
                findings.append({"issue": "invalid_tensor_dimension", "severity": "high", "description": f"Initializer '{init.name}' has non-positive dimension {d}"})
            if d > 1_000_000:
                findings.append({"issue": "outlier_tensor_dimension", "severity": "medium", "description": f"Initializer '{init.name}' has dimension size {d}"})

    external_data = _find_external_data(graph)
    findings.extend(external_data)

    _raw_references = _find_raw_references(data)
    findings.extend(_raw_references)

    return findings


def _scan_raw_heuristics(data: bytes, findings: list[dict]):
    if b"com.microsoft.custom" in data or b"test.ai.onnx" in data:
        findings.append({"issue": "custom_domain_in_bytes", "severity": "critical", "description": "Raw scan found custom operator domain in file bytes"})

    traversal_refs = _check_path_traversal(data)
    findings.extend(traversal_refs)

    oversized = len(data) > 2 * 1024 * 1024 * 1024
    if oversized:
        findings.append({"issue": "excessive_file_size", "severity": "medium", "description": f"ONNX file is {len(data)} bytes"})

    if b"external_data" in data or b"data.location" in data:
        findings.append({"issue": "external_data_reference", "severity": "high", "description": "Raw scan found external data reference"})

    if b"__import__" in data or b"eval(" in data or b"exec(" in data:
        findings.append({"issue": "code_injection_bytes", "severity": "critical", "description": "Raw scan found code injection patterns in ONNX file"})


def _find_external_data(graph) -> list[dict]:
    findings = []
    if not hasattr(graph, "node"):
        return findings
    for node in graph.node:
        for attr in getattr(node, "attribute", []):
            if attr.type == 4:
                ext = getattr(attr, "external_data", [])
                for entry in ext:
                    key = getattr(entry, "key", "")
                    value = getattr(entry, "value", "")
                    if "location" in key.lower() or "path" in key.lower():
                        for pattern in PATH_TRAVERSAL_PATTERNS:
                            if pattern in value:
                                findings.append({"issue": "path_traversal_external_data", "severity": "critical", "description": f"Path traversal in external data reference: {value}"})
    return findings


def _find_raw_references(data: bytes) -> list[dict]:
    findings = []
    decoded = data.decode("utf-8", errors="replace")
    lower = decoded.lower()
    for pattern in PATH_TRAVERSAL_PATTERNS:
        idx = lower.find(pattern)
        if idx >= 0:
            context = decoded[max(0, idx - 40):idx + 40 + len(pattern)]
            findings.append({"issue": "path_traversal_in_bytes", "severity": "critical", "description": f"Path traversal pattern '{pattern}' found in ONNX content: ...{context}..."})
            break
    return findings


def _check_path_traversal(data: bytes) -> list[dict]:
    return _find_raw_references(data)
