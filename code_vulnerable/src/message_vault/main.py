# message vault running on http://localhost:8001

import os
import sqlite3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Message Vault")

VAULT_DB_FILE = os.getenv("VAULT_DB_FILE", "vault.db")

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
def store_message(msg: Message):
    """
    Resource service: persists a single message record into the vault.
    """
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
def get_messages(recipient: str):
    """
    Resource service: returns all messages for a given recipient.
    """
    # --- VULNERABILITY: CWE-862 (Missing Authorization) + COMPOSITION FLAW ---
    # No auth check: the vault trusts any caller, so port 8001 reachable directly
    # lets anyone read any recipient's inbox, bypassing the API entirely.

    conn = sqlite3.connect(VAULT_DB_FILE)
    cursor = conn.cursor()

    # --- VULNERABILITY: CWE-89 (SQL Injection) ---
    # Using direct string formatting instead of parameterized queries 
    query = f"SELECT id, sender, recipient, content FROM messages WHERE recipient = '{recipient}'"
    
    try:
        cursor.execute(query)
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