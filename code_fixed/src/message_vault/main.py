# message vault running on http://localhost:8001

import os
import hmac
import sqlite3
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

app = FastAPI(title="Message Vault")

VAULT_DB_FILE = os.getenv("VAULT_DB_FILE", "vault.db")

# Shared secret authenticating service-to-service calls. The Vault enforces it on
# every request so a direct, unauthenticated caller cannot read or write records,
# even when the port is reachable (FIX: closes the composition / CWE-862 flaw).
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "adfms-internal-service-secret")


def require_internal(x_internal_token: str):
    """Fail-safe default: reject any caller that does not present the internal token."""
    if x_internal_token is None or not hmac.compare_digest(x_internal_token, INTERNAL_SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized caller")


def init_db():
    conn = sqlite3.connect(VAULT_DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            recipient TEXT,
            content TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class Message(BaseModel):
    sender: str
    recipient: str
    content: str

@app.post("/messages")
def store_message(msg: Message, x_internal_token: str = Header(None)):
    """Resource service: persists a single message record into the vault."""
    require_internal(x_internal_token)

    conn = sqlite3.connect(VAULT_DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
        (msg.sender, msg.recipient, msg.content)
    )
    conn.commit()
    conn.close()
    return {"status": "stored", "recipient": msg.recipient}

@app.get("/messages/{recipient}")
def get_messages(recipient: str, x_internal_token: str = Header(None)):
    """Resource service: returns all messages for a given recipient.
    FIX (CWE-862): the internal-token check rejects unauthenticated direct callers.
    FIX (CWE-89): the query is parameterized, so the recipient is always treated
    as a literal value and cannot alter the SQL."""
    require_internal(x_internal_token)

    conn = sqlite3.connect(VAULT_DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT id, sender, recipient, content FROM messages WHERE recipient = ?",
            (recipient,)
        )
        rows = cursor.fetchall()
    except sqlite3.Error as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))

    conn.close()

    messages = [
        {"id": row[0], "sender": row[1], "recipient": row[2], "content": row[3]}
        for row in rows
    ]
    return {"recipient": recipient, "messages": messages}
