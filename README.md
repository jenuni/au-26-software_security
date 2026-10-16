# Project Overview
The project is a Secure Messaging Application built in Python, designed to demonstrate secure software composition and authorization enforcement. The system allows orinary users to securely send, read and export private messages, while granting administrators system auditing and message deletion capabilities. To protect user data and apply security principles like Least Privileges, Defense in Depth and Fail-Safe Defaults, the architecture is distributed across three isolated components: an Application API gateway, a secure Message Vault (Resource Service) and a background Processing Worker.

# au-26-software_security
python -m venv venv
pip install .\external_packages\chat_formatter