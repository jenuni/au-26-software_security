# Project Overview
The project is a Secure Messaging Application built in Python, designed to demonstrate secure software composition and authorization enforcement. The system allows orinary users to securely send, read and export private messages, while granting administrators system auditing and message deletion capabilities. To protect user data and apply security principles like Least Privileges, Defense in Depth and Fail-Safe Defaults, the architecture is distributed across three isolated components: an Application API gateway, a secure Message Vault (Resource Service) and a background Processing Worker.

# Phase 1: Requirements

## Scope and Operation List
**Domain:** Secure Messaging App (Python)
**Protected Resource:** Private Messages
**Operations (Functionalities):**
1. **Send & Read Direct Messages:** Ordinary users send messages and read their own inbox.
2. **System Audit & Message Deletion:** Administrators audit system logs and delete flagged messages.
3. **Export Chat History:** Users export their chat history to a formatted file (Involves Application API, Processing Worker, and Message Vault).

## Asset Register
| Asset | Description | Owner |
| :--- | :--- | :--- |
| **User Identities** | Usernames and session tokens | System |
| **Private Messages** | The actual text data sent between users | Ordinary Users (Sender / Receiver) |
| **Audit Logs** | Records of admin actions and system events | Admin |
| **Application API** | Authenticates users and coordinates requests | System |


## Component and Trust Boundaries
* **Application API:** Authenticates users and coordinates requests. Acts as the initial trust boundary.
* **Message Vault (Resource Service):** Holds the protected records (messages) and enforces authorization permissions for each requested resource and action.
* **Processing Worker:** Performs the chat export job using an external dependency (`chat_formatter`). Operates strictly on the data requested for that specific job.



## Access Control Matrix
| Role | Send Message | Read Own Message | Read Others' Messages | Export Own Chat | Delete Messages |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Ordinary User** | Allow | Allow | Deny | Allow | Deny |
| **Admin** | Allow | Allow | Deny | Allow | Allow |

## STRIDE Threat Model
| Threat Category | Asset at Risk | Threat Description | Impact | Security Control (Requirement) |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | User Identities | An attacker forges a token to impersonate a user. | Authentication, Confidentiality | Strict token validation at the API and Vault boundaries. |
| **Tampering** | Private Messages | A malicious Processing Worker alters messages during export. | Integrity | The Processing Worker is granted read-only access to the Vault. |
| **Repudiation** | Audit Logs | An Admin deletes a message and denies doing so. | Accountability | API logs all admin actions with timestamps. |
| **Information Disclosure** | Private Messages | A user attempts to read another user's inbox. | Confidentiality, Privacy | **Fail-safe defaults:** Vault denies read access unless `user_id` matches the message owner. |
| **Denial of Service** | Application API | Attacker spams the export function to crash the app. | Availability | Rate limiting at the API layer. |
| **Elevation of Privilege** | User Identities | An ordinary user attempts to call the delete endpoint. | Authentication, Confidentiality | **Defense in Depth:** Both API and Vault verify the "Admin" role before deletion. |
