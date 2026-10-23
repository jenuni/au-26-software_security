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