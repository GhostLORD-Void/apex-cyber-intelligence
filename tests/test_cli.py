import json
import sys
from pathlib import Path

from apex.cli import main


def test_cli_writes_valid_json_with_trailing_newline(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    output = tmp_path / "report.json"
    sample.write_text("hello https://example.com", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["apex", "analyze", str(sample), "--out", str(output)])

    main()

    raw = output.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    parsed = json.loads(raw)
    assert parsed["file_name"] == "sample.txt"
