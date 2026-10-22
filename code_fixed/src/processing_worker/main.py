# processing worker running on http://localhost:8002
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import requests
import os
import base64
import json
import hmac
from chat_formatter import format_chat_to_markdown

app = FastAPI(title="Processing Worker", version="1.0.0")

# Internal network route to the Message Vault (Resource Service)
MESSAGE_VAULT_URL = os.getenv("MESSAGE_VAULT_URL", "http://localhost:8001")

# Shared secret authenticating service-to-service calls. The Worker enforces it on
# every request so a direct, unauthenticated caller cannot trigger jobs
# (FIX: closes the composition / CWE-862 flaw), and forwards it to the Vault.
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "adfms-internal-service-secret")
INTERNAL_HEADERS = {"X-Internal-Token": INTERNAL_SERVICE_TOKEN}

# Maximum number of messages accepted in a single import (fail-safe bound).
MAX_IMPORT_MESSAGES = int(os.getenv("MAX_IMPORT_MESSAGES", "1000"))


def require_internal(x_internal_token: str):
    """Fail-safe default: reject any caller that does not present the internal token."""
    if x_internal_token is None or not hmac.compare_digest(x_internal_token, INTERNAL_SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized caller")


class ExportRequest(BaseModel):
    username: str

class ImportRequest(BaseModel):
    username: str
    backup: str  # base64-encoded JSON chat backup


@app.post("/run-export")
def run_export(req: ExportRequest, x_internal_token: str = Header(None)):
    """
    Processing service job: Fetches records from the Message Vault,
    formats them using the external dependency, and returns the export.
    This workflow bridges all 3 components.
    """
    require_internal(x_internal_token)
    try:
        vault_response = requests.get(
            f"{MESSAGE_VAULT_URL}/messages/{req.username}",
            headers=INTERNAL_HEADERS,
        )
        if vault_response.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch records from Message Vault")

        data = vault_response.json()
        messages = data.get("messages", [])

        markdown_output = format_chat_to_markdown(messages)

        return {
            "status": "success",
            "export_format": "markdown",
            "exported_data": markdown_output
        }

    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="Message Vault service unreachable")


@app.post("/import-backup")
def import_backup(req: ImportRequest, x_internal_token: str = Header(None)):
    """
    Processing service job: restores a previously exported chat backup.
    FIX (CWE-502): the backup is parsed as JSON, not unpickled, so a backup blob
    can only ever be data and can never execute code. The structure is validated
    before use (fail-safe defaults / output validation).
    """
    require_internal(x_internal_token)
    try:
        raw = base64.b64decode(req.backup, validate=True)
        messages = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid backup: expected base64-encoded JSON")

    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="Invalid backup: expected a list of messages")
    if len(messages) > MAX_IMPORT_MESSAGES:
        raise HTTPException(status_code=400, detail="Backup too large")

    try:
        stored = 0
        for msg in messages:
            if not isinstance(msg, dict):
                raise HTTPException(status_code=400, detail="Invalid backup: each message must be an object")
            payload = {
                "sender": str(msg.get("sender", req.username)),
                "recipient": str(msg.get("recipient", req.username)),
                "content": str(msg.get("content", "")),
            }
            vault_response = requests.post(
                f"{MESSAGE_VAULT_URL}/messages",
                json=payload,
                headers=INTERNAL_HEADERS,
            )
            if vault_response.status_code == 200:
                stored += 1

        return {"status": "success", "imported": stored}

    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="Message Vault service unreachable")
