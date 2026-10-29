"""APEX HTTP API."""
from __future__ import annotations
import os
from fastapi import FastAPI, UploadFile, File, Header, HTTPException
from pydantic import BaseModel
from .core import analyze_text, analyze_file, validate_scope

app = FastAPI(title="APEX Cyber Intelligence", version="0.1.0", description="Local-first defensive triage API")
MAX_UPLOAD = int(os.getenv("APEX_MAX_UPLOAD_BYTES", "10485760"))
TOKEN = os.getenv("APEX_API_TOKEN")

class TextRequest(BaseModel):
    text: str

class ScopeRequest(BaseModel):
    target: str
    allowed: list[str]

def auth(authorization: str | None):
    if TOKEN and authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Bearer token required")

@app.get("/health")
def health():
    return {"status": "ok", "service": "apex", "version": "0.1.0"}

@app.post("/v1/analyze/text")
def analyze_text_endpoint(body: TextRequest, authorization: str | None = Header(default=None)):
    auth(authorization)
    try:
        return analyze_text(body.text)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))

@app.post("/v1/analyze/file")
async def analyze_file_endpoint(file: UploadFile = File(...), authorization: str | None = Header(default=None)):
    auth(authorization)
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail="file exceeds upload limit")
    import hashlib
    result = {"file_name": file.filename or "upload", "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    try:
        from .core import analyze_text
        result["analysis"] = analyze_text(data.decode("utf-8"))
    except UnicodeDecodeError:
        result["analysis"] = {"text_analysis_skipped": "not valid UTF-8 text"}
    return result

@app.post("/v1/scope/validate")
def scope_endpoint(body: ScopeRequest, authorization: str | None = Header(default=None)):
    auth(authorization)
    return validate_scope(body.target, body.allowed)
