def format_chat_to_markdown(messages: list) -> str:
    """Takes a list of message dicts and formats them into a Markdown string."""
    output = "# Secure Chat Export\n\n"
    for msg in messages:
        sender = msg.get("sender", "Unknown")
        text = msg.get("text", "")
        timestamp = msg.get("timestamp", "N/A")
        output += f"- **[{timestamp}] {sender}**: {text}\n"
    return output