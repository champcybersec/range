# Proxmox Range Management System

A Python Flask web interface for managing Proxmox VMs in competitive cyber training environments. This system provides administrators and users with tools to clone VMs, manage permissions, and integrate with Active Directory authentication.

## Features

- **VM Cloning**: Clone template VMs for individual users or bulk operations
- **User Management**: Integration with Active Directory via Proxmox realm
- **Network Configuration**: Automatic assignment of user-specific virtual networks
- **Permission Management**: Automated ACL configuration for VM access
- **Web Interface**: Simple Flask-based UI for self-service operations

## Architecture

- **Flask Web Application** (`web.py`): Main interface with multiple endpoints
- **Proxmox API Integration**: Using `proxmoxer` library for cluster management
- **User Authentication**: Supports both AD realm and local PVE users
- **Configuration Management**: TOML-based configuration files

## Setup

### Prerequisites

- Python 3.8 or higher
- Access to a Proxmox VE cluster
- Administrative credentials for Proxmox

### Installation

1. Clone the repository:
```bash
git clone https://github.com/champcybersec/range.git
cd range
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create configuration file:
```bash
cp secrets.toml.example secrets.toml
# Edit secrets.toml with your Proxmox credentials
```

4. Run the application:
```bash
python web.py
```

The web interface will be available at `http://localhost:7878`

### Configuration

Create `secrets.toml` in the project root with the following structure:

```toml
[proxmox]
host = "192.168.3.236"      # Proxmox host (without protocol)
user = "root@pam"           # Admin user
password = "your-password"   # Admin password
verify_ssl = false          # SSL verification (true/false)
node = "pve"               # Node name

[web]
admin_password = "changeme"          # Web admin password
default_user_password = "ChangeMe123!" # Default for new PVE users
```

## Web Endpoints

- `/` - Home page with navigation
- `/login` - Admin authentication
- `/admin` - Administrative dashboard
- `/clone` - Individual VM cloning with AD integration
- `/range` - Bulk VM cloning (admin only)
- `/selfserve` - Self-service VM creation (legacy)
- `/ensure` - User management helper (admin only)

## Development

### Code Quality

The project uses modern Python practices:
- Type hints for better IDE support and documentation
- Comprehensive docstrings for all functions
- Modern project structure with `pyproject.toml`

### Development Setup

Install development dependencies:
```bash
pip install -e ".[dev]"
```

Run code formatting:
```bash
black .
```

Run linting:
```bash
flake8 .
```

### Scripts

The `scripts/` directory contains utility scripts for:
- User cleanup (`cleanup_pve_user.py`)
- Range setup (`setup_range.py`)
- VM management (`nuke_*.py`, `set_power_by_name.py`)

## License

See LICENSE file for details.
