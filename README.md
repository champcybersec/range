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
- **Range Management Library** (`rangemgr.py`): Unified API for Proxmox operations
- **Command Line Interface** (`range_cli.py`): CLI tool for administrative tasks
- **TUI Application** (`tui.py`): Interactive menu-driven interface
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

### Command Line Tools

The system provides several command-line tools for administrative tasks:

#### Range CLI (`range_cli.py`)
Unified command-line interface for all range management operations:

```bash
# VM Management
python range_cli.py vm list --pattern ".*range.*"
python range_cli.py vm power start ".*windows.*"
python range_cli.py vm nuke ".*test.*" --dry-run
python range_cli.py vm nuke-gw  # Delete all gateway VMs

# User Management  
python range_cli.py user list --realm ad
python range_cli.py user create testuser password123 --realm pve
python range_cli.py user purge-pve --dry-run

# Network Management
python range_cli.py network list
python range_cli.py network ensure-user john.doe
python range_cli.py network ensure-all  # Create VNets for all AD users

# High-level Range Operations
python range_cli.py range setup john.doe --base-vmid 150
python range_cli.py range setup-all --skip-admins
```

#### Interactive TUI (`tui.py`)
Menu-driven interface for common operations:
```bash
python tui.py
```

### Using the rangemgr Library

The `rangemgr.py` module can be imported and used in custom scripts:

```python
from rangemgr import RangeManager, load_secrets

# Initialize the manager
secrets = load_secrets()
manager = RangeManager(secrets)

# VM operations
vms = manager.vms.get_vms()
manager.vms.nuke_by_pattern(r'.*test.*')
manager.vms.set_power_by_pattern(r'.*windows.*', 'start')

# User operations  
users = manager.users.get_users("ad")
manager.users.create_user("testuser", "password", "pve")

# Network operations
vnet_name = manager.networks.ensure_user_vnet("john.doe")
manager.networks.reload_sdn()

# High-level range setup
success = manager.setup_user_range("john.doe", base_vmid=150)
```

#### Legacy Scripts
Individual scripts are available in the `scripts/` directory but are largely superseded by the unified CLI.

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

The repository provides three main interfaces:

#### rangemgr.py - Core Library
Unified Python library with the following components:
- `RangeManager`: High-level operations for complete range setup
- `VMManager`: VM lifecycle operations (clone, delete, power control)
- `UserManager`: User creation, deletion, and management
- `NetworkManager`: VNet creation and SDN management
- `PoolManager`: Proxmox pool operations

#### range_cli.py - Command Line Interface
Modern CLI tool that replaces individual scripts with unified commands:
- `vm`: VM management (list, power, nuke, clone)
- `user`: User management (list, create, delete, bulk operations)
- `network`: Network operations (VNet management, SDN reload)
- `range`: High-level setup operations

#### Legacy Scripts Directory
The `scripts/` directory contains the original individual scripts:
- User cleanup (`cleanup_pve_user.py`, `purge_pve_users.py`)
- Range setup (`setup_range.py`)
- VM management (`nuke_*.py`, `set_power_by_name.py`)

These are maintained for compatibility but the unified CLI is recommended for new workflows.

## License

See LICENSE file for details.
