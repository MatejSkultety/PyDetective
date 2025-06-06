#!/usr/bin/env bash

set -e

# --- Configuration ---
VENV_DIR="venv"
REQUIREMENTS_FILE="requirements.txt"
PYTHON_MIN_VERSION="3.8"
MAIN_SCRIPT="sudo venv/bin/python3 pydetective.py <package_name>"

# --- Tools to check/install ---
APT_TOOLS=(docker.io python3 python3-pip python3-venv tshark git curl bc)
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
    sudo apt-get update
    for tool in "${APT_TOOLS[@]}"; do
        if ! dpkg -s "$tool" >/dev/null 2>&1; then
            log "Installing $tool..."
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
    $PYTHON_EXEC -c "import sys; from distutils.version import LooseVersion as V; import sys; sys.exit(0 if V(sys.version.split()[0]) >= V('$PYTHON_MIN_VERSION') else 1)"
    if [[ $? -ne 0 ]]; then
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
        sudo apt-get install -y falco
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

    log "Installation finished! You can run the main script with:"
    echo "   $MAIN_SCRIPT"
}

function build_sandbox_docker_image() {
    if [[ -d "sandbox" && -f "sandbox/Dockerfile" ]]; then
        log "Building Docker image from sandbox/Dockerfile..."
        docker build -t pydetective_sandbox_container:latest sandbox
    else
        log "No sandbox/Dockerfile found. Skipping Docker image build."
    fi
}

function build_tcpdump_docker_image() {
    if [[ -d "src/tcpdump" && -f "src/tcpdump/Dockerfile" ]]; then
        log "Building Docker image from src/tcpdump/Dockerfile..."
        docker build -t tcpdump:latest src/tcpdump
    else
        log "No src/tcpdump/Dockerfile found. Skipping Docker image build."
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

build_tcpdump_docker_image
build_sandbox_docker_image
setup_virtualenv
