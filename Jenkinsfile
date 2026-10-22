// Jenkins pipeline for the Messaging Application.
//
// This CI does NOT use Docker: it runs the services as plain Python processes
// for speed and simplicity. The Docker/compose setup in the repo is the
// deployment path. Component dependencies are installed from the pinned
// requirements.txt files, which doubles as the reproducible-build check.
//
// Agent prerequisites: `python3`, `python3-venv`, `git`, and `curl` on PATH.

pipeline {
    agent any

    parameters {
        // Which build to run the pipeline against. `code_vulnerable` is the planted
        // build (gates are expected to fail -> evidence). Switch the default to
        // `code_fixed` once the corrected build exists; that one must pass every gate.
        string(name: 'TARGET_DIR', defaultValue: 'code_vulnerable', description: 'Project directory to build/scan/test (e.g. code_vulnerable or code_fixed)')
        choice(name: 'BANDIT_SEVERITY',   choices: ['medium', 'low', 'high'], description: 'Minimum Bandit severity that blocks the build')
        choice(name: 'BANDIT_CONFIDENCE', choices: ['medium', 'low', 'high'], description: 'Minimum Bandit confidence that blocks the build')
        booleanParam(name: 'FAIL_ON_DEP_VULNS', defaultValue: true, description: 'Fail the build when pip-audit reports vulnerable dependencies')
    }

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    environment {
        TARGET   = "${params.TARGET_DIR}"
        REPORTS  = 'reports'
        VENV     = '.ci-venv'
        SCAN_SRC = "${params.TARGET_DIR}/src"
        SCAN_PKG = "${params.TARGET_DIR}/external_packages"
        PYTHONUNBUFFERED = '1'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                  sh 'rm -rf ${REPORTS} && mkdir -p ${REPORTS}'
            }
        }

        stage('Setup & validate components') {
            steps {
                // One virtualenv holds the CI tools AND the component dependencies.
                // Installing each component's pinned requirements is the build-
                // validation: an unresolved or unlisted dependency fails here.
                sh '''
                    # Pick a Python that matches the app's target (3.10-3.12).
                    PYBIN=""
                    for c in python3.12 python3.11 python3.10 python3; do
                        if command -v "$c" >/dev/null 2>&1; then PYBIN="$c"; break; fi
                    done
                    echo "Using interpreter: $PYBIN ($($PYBIN --version 2>&1))"

                    "$PYBIN" -m venv ${VENV}
                    . ${VENV}/bin/activate
                    python -m pip install --upgrade pip
                    pip install bandit pip-audit pytest requests

                    pip install -r ${TARGET}/src/app_api/requirements.txt
                    pip install -r ${TARGET}/src/message_vault/requirements.txt
                    pip install -r ${TARGET}/src/processing_worker/requirements.txt
                    # External helper package (installed from controlled local source).
                    pip install ${TARGET}/external_packages/chat_formatter

                    bandit --version
                    pip-audit --version
                '''
            }
        }

        stage('Static analysis (Bandit)') {
            steps {
                sh '''
                    . ${VENV}/bin/activate
                    # Always produce reports (do not fail here) so they can be archived.
                    bandit -r ${SCAN_SRC} ${SCAN_PKG} -f json -o ${REPORTS}/bandit.json || true
                    bandit -r ${SCAN_SRC} ${SCAN_PKG} -f txt  -o ${REPORTS}/bandit.txt  || true
                '''
            }
        }

        stage('Gate: Static analysis') {
            steps {
                // Re-run only at the blocking threshold; a non-zero exit fails the stage.
                sh '''
                    . ${VENV}/bin/activate
                    echo "Blocking on Bandit severity>=${BANDIT_SEVERITY}, confidence>=${BANDIT_CONFIDENCE}"
                    bandit -r ${SCAN_SRC} ${SCAN_PKG} \
                        --severity-level ${BANDIT_SEVERITY} \
                        --confidence-level ${BANDIT_CONFIDENCE} \
                        -q
                '''
            }
        }

        stage('Dependency analysis (pip-audit)') {
            steps {
                // Audit every component's declared dependencies. Reports are always
                // written; the gate decision is enforced in the next stage.
                sh '''
                    . ${VENV}/bin/activate
                    status=0
                    for req in \
                        ${TARGET}/src/app_api/requirements.txt \
                        ${TARGET}/src/message_vault/requirements.txt \
                        ${TARGET}/src/processing_worker/requirements.txt ; do
                        name=$(echo "$req" | awk -F/ '{print $(NF-1)}')
                        echo "Auditing $name ($req)"
                        pip-audit -r "$req" -f json -o ${REPORTS}/pip-audit-$name.json || status=1
                        pip-audit -r "$req" -f columns          > ${REPORTS}/pip-audit-$name.txt  2>&1 || true
                    done
                    echo "$status" > ${REPORTS}/.dep-audit-status
                '''
            }
        }

        stage('Gate: Dependencies') {
            steps {
                script {
                    def status = sh(script: 'cat ${REPORTS}/.dep-audit-status', returnStdout: true).trim()
                    if (status != '0') {
                        if (params.FAIL_ON_DEP_VULNS) {
                            error("Dependency analysis found vulnerable packages (see pip-audit reports). Blocking release.")
                        } else {
                            echo "WARNING: vulnerable dependencies found, but FAIL_ON_DEP_VULNS is disabled."
                        }
                    } else {
                        echo "No known-vulnerable dependencies reported."
                    }
                }
            }
        }

        stage('Functional & authorization tests') {
            steps {
                // Start the three services as a fresh environment, wait for the API,
                // run the tests, then stop the services
                sh '''
                    . ${VENV}/bin/activate
                    WS="$PWD"
                    mkdir -p "$WS/${REPORTS}/svc-logs"

                    # Each service runs with its own directory as CWD (mirroring the
                    # Docker WORKDIR), so relative paths like ./documents and the
                    # sqlite files resolve exactly as they do in production.
                    rm -f ${TARGET}/src/app_api/auth.db ${TARGET}/src/message_vault/vault.db || true

                    ( cd ${TARGET}/src/message_vault    && exec uvicorn main:app --host 127.0.0.1 --port 8001 ) > "$WS/${REPORTS}/svc-logs/message_vault.log" 2>&1 &
                    VAULT_PID=$!
                    ( cd ${TARGET}/src/processing_worker && exec uvicorn main:app --host 127.0.0.1 --port 8002 ) > "$WS/${REPORTS}/svc-logs/processing_worker.log" 2>&1 &
                    WORKER_PID=$!
                    ( cd ${TARGET}/src/app_api           && exec uvicorn main:app --host 127.0.0.1 --port 8000 ) > "$WS/${REPORTS}/svc-logs/app_api.log" 2>&1 &
                    API_PID=$!

                    stop_services() { kill $API_PID $WORKER_PID $VAULT_PID 2>/dev/null || true; }
                    trap stop_services EXIT

                    # Wait for the Application API (FastAPI serves /openapi.json).
                    up=0
                    for i in $(seq 1 30); do
                        if curl -fsS http://127.0.0.1:8000/openapi.json > /dev/null 2>&1; then
                            echo "API is up"; up=1; break
                        fi
                        echo "waiting for API... ($i)"; sleep 1
                    done
                    if [ "$up" != "1" ]; then echo "API did not come up"; cat "$WS/${REPORTS}/svc-logs/"*.log; exit 1; fi

                    # Backup wire format the Import feature expects differs by build:
                    # pickle for the vulnerable build, json for the fixed one.
                    case "${TARGET}" in
                        *fixed*) export BACKUP_FORMAT=json ;;
                        *)       export BACKUP_FORMAT=pickle ;;
                    esac
                    echo "Using BACKUP_FORMAT=${BACKUP_FORMAT}"

                    set +e
                    pytest tests/ -v --junitxml="$WS/${REPORTS}/pytest-junit.xml"
                    rc=$?
                    set -e
                    stop_services
                    exit $rc
                '''
            }
        }
    }

    post {
        always {
            // Publish test results and archive all analysis/test artifacts.
            junit allowEmptyResults: true, testResults: "${REPORTS}/pytest-junit.xml"
            archiveArtifacts artifacts: "${REPORTS}/**", allowEmptyArchive: true, fingerprint: true
        }
        cleanup {
            sh 'rm -rf ${VENV} || true'
        }
    }
}
