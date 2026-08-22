#!/bin/bash
# Epic OSINT Toolkit Setup Script for Linux/Mac
set -euo pipefail

echo "Epic OSINT Toolkit - Setup"
echo "========================="
echo ""

cd "$(dirname "$0")"

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.10 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"

create_venv() {
    if [ -d "venv" ]; then
        echo "Virtual environment already exists, skipping..."
        return
    fi

    if command -v uv &> /dev/null; then
        echo "Creating virtual environment with uv..."
        uv venv venv
    elif python3 -m venv -h &> /dev/null; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    else
        echo "ERROR: Cannot create a virtual environment."
        echo "Install one of: python3-venv (apt) or uv (https://docs.astral.sh/uv/)"
        exit 1
    fi
    echo "Virtual environment created!"
}

install_deps() {
    # shellcheck disable=SC1091
    source venv/bin/activate
    echo "Installing hashed lockfile (requirements.txt)..."
    if command -v uv &> /dev/null; then
        uv pip install --require-hashes -r requirements.txt
    else
        python -m pip install --require-hashes -r requirements.txt
    fi
}

echo ""
create_venv
echo ""
install_deps

mkdir -p reports
chmod +x osint_toolkit.py setup.sh

echo ""
echo "========================="
echo "Setup completed successfully!"
echo ""
echo "Recommended: use the interactive TUI"
echo "  1. Activate:  source venv/bin/activate"
echo "  2. Launch:    python osint_toolkit.py"
echo "     (or)       python osint_toolkit.py --tui"
echo ""
echo "TUI tips:"
echo "  - Left pane = modules, right pane = feature / report"
echo "  - Arrow keys / j k  navigate   Enter open   Esc/q back"
echo "  - Start with Auto Scan or pick a module from the menu"
echo ""
echo "CLI still works when you prefer flags, e.g.:"
echo "  python osint_toolkit.py -t example.com --auto"
echo "  python osint_toolkit.py -t example.com --dns --ssl"
echo ""
