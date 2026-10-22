// CI for the Secure Messaging Application (Assignment I).
// Static analysis (Bandit) + dependency analysis (pip-audit), then builds the
// Docker images and runs the test suite against the live container stack.
// code_vulnerable is expected to FAIL the gates (evidence); code_fixed must pass.
// Agent needs: python3(-venv), git, curl, docker + docker compose v2.

pipeline {
    agent any

    parameters {
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
        COMPOSE_DIR = "${params.TARGET_DIR}"
        REPORTS     = 'reports'
        VENV        = '.ci-venv'
        SCAN_SRC    = "${params.TARGET_DIR}/src"
        SCAN_PKG    = "${params.TARGET_DIR}/external_packages"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'rm -rf ${REPORTS} && mkdir -p ${REPORTS}/svc-logs'
            }
        }

        stage('Setup tooling') {
            steps {
                // Venv for the CI tools only; the app runs in containers.
                sh '''
                    PYBIN=""
                    for c in python3.12 python3.11 python3.10 python3; do
                        if command -v "$c" >/dev/null 2>&1; then PYBIN="$c"; break; fi
                    done
                    echo "Using interpreter: $PYBIN ($($PYBIN --version 2>&1))"

                    "$PYBIN" -m venv ${VENV}
                    . ${VENV}/bin/activate
                    python -m pip install --upgrade pip
                    pip install bandit pip-audit pytest requests
                    docker compose version
                '''
            }
        }

        stage('Static analysis (Bandit)') {
            steps {
                sh '''
                    . ${VENV}/bin/activate
                    bandit -r ${SCAN_SRC} ${SCAN_PKG} -f json -o ${REPORTS}/bandit.json || true
                    bandit -r ${SCAN_SRC} ${SCAN_PKG} -f txt  -o ${REPORTS}/bandit.txt  || true
                '''
            }
        }

        stage('Gate: Static analysis') {
            steps {
                // Non-zero exit (findings at/above threshold) fails the build.
                sh '''
                    . ${VENV}/bin/activate
                    bandit -r ${SCAN_SRC} ${SCAN_PKG} \
                        --severity-level ${BANDIT_SEVERITY} \
                        --confidence-level ${BANDIT_CONFIDENCE} \
                        -q
                '''
            }
        }

        stage('Dependency analysis (pip-audit)') {
            steps {
                sh '''
                    . ${VENV}/bin/activate
                    status=0
                    for req in \
                        ${COMPOSE_DIR}/src/app_api/requirements.txt \
                        ${COMPOSE_DIR}/src/message_vault/requirements.txt \
                        ${COMPOSE_DIR}/src/processing_worker/requirements.txt ; do
                        name=$(echo "$req" | awk -F/ '{print $(NF-1)}')
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
                    if (status != '0' && params.FAIL_ON_DEP_VULNS) {
                        error("Dependency analysis found vulnerable packages (see pip-audit reports). Blocking release.")
                    } else if (status != '0') {
                        echo "WARNING: vulnerable dependencies found, but FAIL_ON_DEP_VULNS is disabled."
                    }
                }
            }
        }

        stage('Build images') {
            steps {
                dir("${COMPOSE_DIR}") {
                    sh 'docker compose build'
                }
            }
        }

        stage('Functional & authorization tests') {
            steps {
                // Fresh container stack (no volumes -> seeded DBs), tested over HTTP.
                dir("${COMPOSE_DIR}") {
                    sh 'docker compose down -v --remove-orphans || true'
                    sh 'docker compose up -d'
                }
                sh '''
                    . ${VENV}/bin/activate

                    up=0
                    for i in $(seq 1 60); do
                        if curl -fsS http://127.0.0.1:8000/openapi.json > /dev/null 2>&1; then
                            echo "API is up"; up=1; break
                        fi
                        echo "waiting for API... ($i)"; sleep 2
                    done
                    if [ "$up" != "1" ]; then echo "API did not come up"; exit 1; fi

                    # Backup format: pickle for the vulnerable build, json for the fixed one.
                    case "${COMPOSE_DIR}" in
                        *fixed*) export BACKUP_FORMAT=json ;;
                        *)       export BACKUP_FORMAT=pickle ;;
                    esac

                    pytest tests/ -v --junitxml=${REPORTS}/pytest-junit.xml
                '''
            }
        }
    }

    post {
        always {
            dir("${COMPOSE_DIR}") {
                sh 'docker compose logs --no-color > ../${REPORTS}/svc-logs/docker-compose.log 2>&1 || true'
                sh 'docker compose down -v --remove-orphans || true'
            }
            junit allowEmptyResults: true, testResults: "${REPORTS}/pytest-junit.xml"
            archiveArtifacts artifacts: "${REPORTS}/**", allowEmptyArchive: true, fingerprint: true
        }
        cleanup {
            sh 'rm -rf ${VENV} || true'
        }
    }
}
