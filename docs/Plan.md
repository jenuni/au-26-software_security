# Phase 1: Requirements

## Scope and Operation List
**Domain:** Messaging Application (Python)
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

## Deliverables
* **Three working components**, each running as a separate Docker container and communicating only over HTTP: Application API (`src/app_api`, port 8000), Processing Worker (`src/processing_worker`, port 8002), and Message Vault (`src/message_vault`, port 8001). Orchestrated by `docker-compose.yml`.
* **External dependency**: the `chat_formatter` helper package (`external_packages/chat_formatter`) is built and installed as a real package in the Worker's Dockerfile (`pip install external_packages/chat_formatter`), not copied into component source. This is the "external" dependency used by the export functionality.
* **Reproducible builds**: pinned dependencies in each component's `requirements.txt`.

## Dependency Trust and Supply Chain
| Concern | Control | Lifecycle activity |
| :--- | :--- | :--- |
| Known-vulnerable third-party packages | `pip-audit` on every component's declared dependencies | CI "Dependency analysis" stage |
| Unapproved / unlisted artifacts | Only pinned, declared packages are installed; `chat_formatter` comes from a controlled local source, never PyPI | Docker build + dependency audit |
| Insecure code patterns | `bandit` static analysis over `src/` and `external_packages/` | CI "Static analysis" stage |

## Lifecycle Activity (CI)
The `Jenkinsfile` runs on every push and pull request and performs: validate/build the components (installing each component's pinned `requirements.txt`, so an unresolved or unlisted dependency fails the build), **static analysis** (Bandit), and **dependency analysis** (pip-audit) (for Phase 2). CI runs the services as plain Python processes rather than containers; the Docker/compose setup is the deployment path. All reports are archived as build artifacts. (The functional/authorization test stage belongs to Phase 3.)

## Gate Decision
**Blocking criteria:** the build is rejected if Bandit reports findings at or above the configured severity/confidence threshold, or if pip-audit reports vulnerable dependencies.
**Expected result on the vulnerable build: FAIL**. Bandit flags the planted CWE-89 (string-formatted SQL) and CWE-502 (`pickle.loads`), and pip-audit flags the outdated `requests==2.31.0`. This failing run is retained as evidence that the gate works.
**Expected result on the fixed build (`code_fixed/`): PASS**. The corrected code uses parameterized queries and safe deserialization (removing the Bandit findings) and updates the flagged dependencies, so no blocking finding remains and the build is cleared for release.

# Phase 3: Testing

## Deliverables
* An automated test suite (`tests/`) that runs against the live, running stack over HTTP and is organised into three marked categories: `functional`, `authorization`, and `security`.

## Test Coverage
| Category | What it checks |
| :--- | :--- |
| **Functional** | All seeded users log in (bad password rejected); send a message; export spanning all three components; Admin import restored and visible via export. |
| **Authorization** | Missing/invalid token -> 403 (fail-safe defaults); ordinary user denied the Admin-only import -> 403 (least privilege); export scoped to the caller's own inbox; session token rejected after its TTL -> 401 (validity period). |
| **Security** | CWE-22: path traversal on `/download` is blocked. CWE-89: an injected recipient does not return other users' rows. Composition/CWE-862: direct, unauthenticated calls to the Worker and Vault are rejected. CWE-502: a malicious serialized backup does not execute code during import. |

## Gate Decision
**Blocking criteria:** any failing functional or authorization test blocks the release, and the security tests must pass on the build being released.
**Expected result on the vulnerable build: FAIL**. The security tests fail because the planted vulnerabilities are exploitable.
**Expected result on the fixed build: PASS**. Functional, authorization, and security tests all pass, clearing the release.