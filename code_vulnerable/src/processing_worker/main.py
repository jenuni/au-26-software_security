# processing worker running on http://localhost:8002
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os
from chat_formatter import format_chat_to_markdown

app = FastAPI(title="Processing Worker", version="1.0.0")

# Internal network route to the Message Vault (Resource Service)
MESSAGE_VAULT_URL = os.getenv("MESSAGE_VAULT_URL", "http://localhost:8001")

class ExportRequest(BaseModel):
    username: str

@app.post("/run-export")
def run_export(req: ExportRequest):
    """
    Processing service job: Fetches records from the Message Vault,
    formats them using the external dependency, and returns the export.
    This workflow bridges all 3 independent components.
    """
    try:
        # --- VULNERABILITY: CWE-862 (Missing Authorization) ---
        # No authentication or authorization checks are performed here, allowing any user to retrieve messages for any recipient.
        
        # Worker requests allowed records from Vault
        vault_response = requests.get(f"{MESSAGE_VAULT_URL}/messages/{req.username}")
        
        if vault_response.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch records from Message Vault")
        
        data = vault_response.json()
        messages = data.get("messages", [])

        # Process the data using the external helper package dependency
        markdown_output = format_chat_to_markdown(messages)

        return {
            "status": "success",
            "export_format": "markdown",
            "exported_data": markdown_output
        }
        
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="Message Vault service unreachable")


