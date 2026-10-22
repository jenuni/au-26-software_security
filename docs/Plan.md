# Phase 1: Requirements

## Scope and Operation List
**Domain:** Secure Messaging App (Python)
**Protected Resource:** Private Messages
**Operations (Functionalities):**
1. **Send Message:** Any authenticated user sends a message to a recipient (Application API -> Message Vault).
2. **Export Chat History:** Any authenticated user exports their own messages to a formatted Markdown file via the external `chat_formatter` dependency (Involves all three components: Application API -> Processing Worker -> Message Vault).
3. **Import Chat Backup:** Admin-only restricted action that restores a previously exported backup, which is deserialized and written back to the vault (Involves all three components: Application API -> Processing Worker -> Message Vault).
4. **Supporting operation:** View Terms of Service / Privacy Policy. Any caller downloads static public documents (Application API).

## Asset Register
| Asset | Description | Owner |
| :--- | :--- | :--- |
| **User Credentials** | Usernames, roles, and salted PBKDF2 password hashes, stored in the Application API's `auth.db` (separate from the message store) | System |
| **Session Tokens** | Random bearer tokens issued at login that bind a user's identity and role for a limited validity period (TTL), held in the API's in-memory session store | System |
| **Private Messages** | The actual text data sent between users, stored in the Message Vault's `vault.db` | Ordinary Users (Sender / Recipient) |
| **Public Documents** | Terms of Service and Privacy Policy text files served to any caller via the Application API's `/download` endpoint | System |
| **Application API** | Authenticates users and coordinates requests across components | System |


## Component and Trust Boundaries
The application runs as three independent processes (separate Docker containers) that communicate only over HTTP. Each inter-service hop crosses a trust boundary: a component must not assume that a request reaching it has already been authenticated or authorized by the caller. The user is the outermost untrusted actor, and the external `chat_formatter` dependency is untrusted code pulled into the Processing Worker.

* **Application API (port 8000):** The only component intended to face the user. Establishes identity by authenticating against `auth.db`, issues and validates session tokens, and enforces role-based authorization before coordinating work on the other services. It is the primary policy decision point and the first trust boundary.
* **Processing Worker (port 8002):** Performs batch jobs (export and import) using the external `chat_formatter` dependency. It should operate strictly on the data for the specific job it was given and should not be reachable except via the Application API.
* **Message Vault / Resource Service (port 8001):** Holds the protected records (messages) in `vault.db`. As the resource owner it is responsible for enforcing permissions on every read and write, including requests that arrive from the Worker, and must not assume another component already checked authority.



## Access Control Matrix
| Role | Send Message | Export Own Chat | Import Backup | View ToS / Privacy |
| :--- | :--- | :--- | :--- | :--- |
| **Ordinary User** | Allow | Allow (own messages only) | Deny | Allow |
| **Admin** | Allow | Allow (own messages only) | Allow | Allow |


## STRIDE Threat Model
| Threat Category | Asset at Risk | Threat Description | Impact | Security Control (Requirement) |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Session Tokens | An attacker guesses or forges a token to impersonate a user. | Authentication, Confidentiality | High-entropy random tokens (`secrets.token_urlsafe`) validated server-side on every request, credentials checked against salted PBKDF2 hashes, never plaintext. |
| **Tampering** | Private Messages | A caller writes or alters messages belonging to another user (e.g. via the import path or a direct call to the Vault). | Integrity | *Intended:* the Vault authorizes every write against the record owner. *Not enforced in the vulnerable build, this is the planted composition flaw.* |
| **Repudiation** | Private Messages | An Admin imports or alters messages and later denies the action. | Accountability | *Production requirement:* append-only audit logging of privileged actions with timestamps and actor identity. Not implemented in this prototype. |
| **Information Disclosure** | Private Messages | A user reads another user's inbox. | Confidentiality, Privacy | **Fail-safe defaults:** protected endpoints return 403 unless a valid, unexpired session is present, and export is scoped to the caller's own username. *The composition flaw bypasses this when the Worker/Vault are reached directly.* |
| **Denial of Service** | Application API | An attacker spams export/import jobs to exhaust resources. | Availability | *Production requirement:* rate limiting and request quotas at the API. Not implemented in this prototype. |
| **Elevation of Privilege** | Session Tokens | An ordinary user invokes the Admin-only import action. | Authorization, Integrity | **Least privilege:** the API enforces an Admin role check on `/import`. **Defense in depth** (target state) adds the same check at the Worker/Vault; the missing cross-tier check is the planted composition flaw. |

## Gate Decision
**Reviewed:** the three-component architecture meets the scope, the assets and their owners are identified, two roles with a privileged restricted action (Admin-only import) are defined, and every STRIDE threat maps to a control or a documented gap.
**Decision: PASS**

# Phase 2: Implementation and Build
