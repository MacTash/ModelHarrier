"""Integration tests using the optional ONNX and HDF5 parser dependencies."""

from __future__ import annotations

import io
import json

import pytest

from model_harrier.scan.formats.keras import scan_keras
from model_harrier.scan.formats.onnx import scan_onnx


def _onnx_bytes(domain: str = "") -> bytes:
    onnx = pytest.importorskip("onnx")
    from onnx import TensorProto, helper

    node = helper.make_node("Identity", ["input"], ["output"], domain=domain)
    graph = helper.make_graph(
        [node], "integration",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])],
    )
    imports = [helper.make_opsetid("", 13)]
    if domain:
        imports.append(helper.make_opsetid(domain, 1))
    return helper.make_model(graph, opset_imports=imports).SerializeToString()


def _hdf5_bytes(model_config: dict) -> bytes:
    h5py = pytest.importorskip("h5py")
    output = io.BytesIO()
    with h5py.File(output, "w") as model:
        model.attrs["model_config"] = json.dumps(model_config)
    return output.getvalue()


def test_real_onnx_parser_accepts_benign_graph() -> None:
    findings = scan_onnx(_onnx_bytes())

    assert not [item for item in findings if item["severity"] in ("high", "critical")]
    assert "onnx_not_installed" not in {item["issue"] for item in findings}


def test_real_onnx_parser_detects_custom_operator_domain() -> None:
    findings = scan_onnx(_onnx_bytes("test.ai.onnx"))

    assert "custom_operator_domain" in {item["issue"] for item in findings}


def test_real_onnx_parser_checks_initializer_external_data_path() -> None:
    onnx = pytest.importorskip("onnx")
    from onnx import TensorProto, helper

    tensor = helper.make_tensor("weights", TensorProto.FLOAT, [1], [0.0])
    tensor.data_location = TensorProto.EXTERNAL
    location = tensor.external_data.add()
    location.key = "location"
    location.value = "../../outside.bin"
    graph = helper.make_graph([], "external", [], [], initializer=[tensor])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])

    findings = scan_onnx(model.SerializeToString())

    assert "path_traversal_external_data" in {item["issue"] for item in findings}


def test_real_hdf5_parser_accepts_benign_model_config() -> None:
    config = {"class_name": "Functional", "config": {"layers": [{"class_name": "Dense", "config": {"units": 4}}]}}

    findings = scan_keras(_hdf5_bytes(config))

    assert findings == []


def test_real_hdf5_parser_detects_lambda_layer_config() -> None:
    config = {"class_name": "Functional", "config": {"layers": [{"class_name": "Lambda", "config": {}}]}}

    findings = scan_keras(_hdf5_bytes(config))

    assert "lambda_layer_in_layers" in {item["issue"] for item in findings}
