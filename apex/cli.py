"""Command-line offline evidence triage."""
import argparse, json
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
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(report + "\\n")
        print(f"Report written to {args.out}")

if __name__ == "__main__":
    main()
