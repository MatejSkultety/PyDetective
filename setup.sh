#!/usr/bin/env bash

set -e

# --- Configuration ---
VENV_DIR="venv"
REQUIREMENTS_FILE="requirements.txt"
PYTHON_MIN_VERSION="3.7"
DB_NAME="pydetective_db"
DB_USER="pydetective_user"
DB_PASS="pydetective_password"
MAIN_SCRIPT="main.py"

# --- Tools to check/install ---
APT_TOOLS=(docker.io python3 python3-pip python3-venv git curl bc)
SPECIAL_TOOLS=(sysdig falco)

# --- Helpers ---
function log() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

function error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
    exit 1
}

function check_command() {
    command -v "$1" >/dev/null 2>&1
}

function install_apt_tools() {
    for tool in "${APT_TOOLS[@]}"; do
        if ! dpkg -s "$tool" >/dev/null 2>&1; then
            log "Installing $tool..."
            sudo apt-get update
            sudo apt-get install -y "$tool"
        else
            log "$tool is already installed."
        fi
    done
}

function ensure_python() {
    if check_command python3; then
        PYTHON_EXEC=$(command -v python3)
    else
        error "Python 3 not found after attempted install."
    fi

    PYTHON_VERSION=$($PYTHON_EXEC -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$PYTHON_VERSION < $PYTHON_MIN_VERSION" | bc) -eq 1 ]]; then
        error "Python version must be >= $PYTHON_MIN_VERSION. Found: $PYTHON_VERSION"
    fi

    export PYTHON_EXEC
}

function install_sysdig() {
    if ! check_command sysdig; then
        log "Installing Sysdig..."
        curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash
    else
        log "Sysdig is already installed."
    fi
}

function install_falco() {
    if ! check_command falco; then
        log "Installing Falco..."
        curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
        sudo apt-get update && sudo apt-get install -y falco
    else
        log "Falco is already installed."
    fi
}

function setup_virtualenv() {
    log "Creating virtual environment..."
    $PYTHON_EXEC -m venv "$VENV_DIR"

    log "Activating virtual environment..."
    # shellcheck disable=SC1090
    source "$VENV_DIR/bin/activate"

    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        log "Installing Python dependencies..."
        pip install --upgrade pip
        pip install -r "$REQUIREMENTS_FILE"
    else
        log "No requirements.txt found. Skipping Python package installation."
    fi
}

function setup_database() {
    log "Installing MySQL Server..."
    sudo apt-get update
    sudo apt-get install -y mysql-server

    log "Configuring MySQL database and user..."
    sudo mysql <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
    log "Database setup complete."
}

function build_sandbox_docker_image() {
    if [[ -d "sandbox" && -f "sandbox/Dockerfile" ]]; then
        log "Building Docker image from sandbox/Dockerfile..."
        docker build -t pydetective_sandbox_container:latest sandbox
    else
        log "No sandbox/Dockerfile found. Skipping Docker image build."
    fi
}

function run_main() {
    if [[ -f "$MAIN_SCRIPT" ]]; then
        log "Running $MAIN_SCRIPT..."
        $PYTHON_EXEC "$MAIN_SCRIPT"
    else
        log "No $MAIN_SCRIPT found. Activate the environment with:"
        echo "  source $VENV_DIR/bin/activate"
    fi
}

# --- Main Execution ---
log "Installing APT packages..."
install_apt_tools

log "Ensuring Python and pip..."
ensure_python

log "Checking and installing Sysdig and Falco..."
install_sysdig
install_falco

setup_virtualenv
setup_database
build_sandbox_docker_image

run_main
