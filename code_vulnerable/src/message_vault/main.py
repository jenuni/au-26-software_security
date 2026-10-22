# message vault running on http://localhost:8001

import sqlite3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Message Vault")

DB_FILE = "vault.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
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
    conn = sqlite3.connect(DB_FILE)
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
    # --- VULNERABILITY: CWE-862 (Composition Vulnerability and Missing Authorization) ---
    # No authentication or authorization checks are performed here, allowing any user to retrieve messages for any recipient.

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # --- VULNERABILITY: CWE-89 (SQL Injection) ---
    # Using direct string formatting instead of parameterized queries 
    query = f"SELECT id, sender, recipient, content FROM messages WHERE recipient = '{recipient}'"
    
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except sqlite3.Error as e:
        conn.close()
        raise HTTPException(status_code=400, database_error=str(e))
        
    conn.close()
    
    messages = [
        {"id": row[0], "sender": row[1], "recipient": row[2], "content": row[3]}
        for row in rows
    ]
    return {"recipient": recipient, "messages": messages}