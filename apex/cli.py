"""Command-line offline evidence triage."""
import argparse
import json
from pathlib import Path

from .core import analyze_file


def main():
    parser = argparse.ArgumentParser(description="APEX offline file triage")
    parser.add_argument("analyze", choices=["analyze"])
    parser.add_argument("path")
    parser.add_argument("--out", default="-", help="JSON output path or - for stdout")
    args = parser.parse_args()
    report = json.dumps(analyze_file(args.path), indent=2)
    if args.out == "-":
        print(report)
    else:
        output_path = Path(args.out)
        output_path.write_text(report + "\n", encoding="utf-8")
        print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
