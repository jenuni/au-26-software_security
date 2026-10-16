from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ADFMS Message Vault", version="1.0.0")

# In-memory storage for private messages 
MESSAGE_DATABASE = []

class StoreMessageModel(BaseModel):
    sender: str
    recipient: str
    text: str

@app.post("/store")
def store_message(msg: StoreMessageModel):
    """Stores a new private message in the vault."""
    message_entry = {
        "id": len(MESSAGE_DATABASE) + 1,
        "sender": msg.sender,
        "recipient": msg.recipient,
        "text": msg.text
    }
    MESSAGE_DATABASE.append(message_entry)
    return {"status": "success", "message_id": message_entry["id"]}

@app.get("/messages/{username}")
def get_user_messages(username: str):
    """Retrieves messages for a specific user."""
    user_messages = [
        m for m in MESSAGE_DATABASE 
        if m["sender"] == username or m["recipient"] == username
    ]
    return {"messages": user_messages}

@app.delete("/messages/{message_id}")
def delete_message(message_id: int):
    """Deletes a specific message by ID."""
    global MESSAGE_DATABASE
    initial_len = len(MESSAGE_DATABASE)
    MESSAGE_DATABASE = [m for m in MESSAGE_DATABASE if m["id"] != message_id]
    
    if len(MESSAGE_DATABASE) == initial_len:
        raise HTTPException(status_code=404, detail="Message not found")
        
    return {"status": "success", "deleted_id": message_id}