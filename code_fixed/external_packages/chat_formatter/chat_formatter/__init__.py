def format_chat_to_markdown(messages: list) -> str:
    """Takes a list of message dicts and formats them into a Markdown string."""
    output = "# Secure Chat Export\n\n"
    for msg in messages:
        sender = msg.get("sender", "Unknown")
        recipient = msg.get("recipient", "Unknown")
        content = msg.get("content", "")
        output += f"- **{sender} -> {recipient}**: {content}\n"
    return output