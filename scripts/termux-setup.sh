#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
pkg update -y
pkg install -y python git
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
printf '\\nAPEX setup and tests complete. Start with:\\nuvicorn apex.api:app --host 127.0.0.1 --port 8000\\n'
