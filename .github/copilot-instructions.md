# Proxmox Range Management System - GitHub Copilot Instructions

## Project Overview

This is a Python-based Flask web application for managing Proxmox VMs in competitive cyber training environments. The system provides administrators and users with tools to clone VMs, manage permissions, and integrate with Active Directory authentication.

### Purpose
- **Training Environment Management**: Automate VM lifecycle for cybersecurity competitions and training
- **User Self-Service**: Allow users to clone VMs through web interface or CLI
- **Active Directory Integration**: Seamless authentication and user management
- **Network Isolation**: Automatic VNet creation for user isolation

## Architecture & Components

### Core Library (`rangemgr.py`)
- **RangeManager**: Main orchestration class
- **VMManager**: VM lifecycle operations (create, clone, delete, power control)
- **UserManager**: User and authentication management 
- **NetworkManager**: VNet and SDN configuration management

### Web Interface (`web.py`)
- Flask application with multiple endpoints
- Admin dashboard for bulk operations
- Self-service VM cloning interface
- Health monitoring and status pages

### Command Line Interface (`range_cli.py`)
- Unified CLI tool replacing individual scripts
- Supports all VM, user, and network operations
- Dry-run support for safe testing
- Consistent help documentation

### Interactive TUI (`tui.py`)
- Menu-driven interface for common operations
- Simplified workflow for administrators

## Key Features

- **VM Cloning**: Clone template VMs for individual users or bulk operations
- **User Management**: Integration with Active Directory via Proxmox realm
- **Network Configuration**: Automatic assignment of user-specific virtual networks
- **Permission Management**: Automated ACL configuration for VM access
- **Web Interface**: Simple Flask-based UI for self-service operations

## Development Setup

### Prerequisites
- Python 3.8 or higher
- Access to a Proxmox VE cluster
- Administrative credentials for Proxmox

### Installation
```bash
git clone https://github.com/champcybersec/range.git
cd range
pip install -r requirements.txt
cp secrets.toml.example secrets.toml
# Edit secrets.toml with your Proxmox credentials
```

### Configuration
Create `secrets.toml` in the project root:
```toml
[proxmox]
host = "192.168.3.236"      # Proxmox host (without protocol)
user = "root@pam"           # Admin user
password = "your-password"   # Admin password
verify_ssl = false          # SSL verification (true/false)
node = "pve"               # Node name

[web]
admin_password = "changeme"          # Web admin password
```

### Development Commands
- `python web.py` - Start web server (localhost:7878)
- `python dev.py check` - Run development checks
- `python range_cli.py --help` - View CLI options
- `python tui.py` - Start interactive TUI

## API Endpoints

### Web Interface Routes
- `GET /` - Home page with navigation
- `GET /health` - Health check and system status
- `GET /login` - Admin authentication
- `GET /admin` - Administrative dashboard
- `GET /clone` - Individual VM cloning with AD integration
- `GET /range` - Bulk VM cloning (admin only)
- `GET /ensure` - User management helper (admin only)

## Common Use Cases

### VM Operations
```python
from rangemgr import RangeManager

manager = RangeManager()

# VM operations
manager.vms.nuke_by_pattern(r'.*test.*')
manager.vms.set_power_by_pattern(r'.*windows.*', 'start')

# User operations
manager.users.create_user("testuser", "password")
manager.users.purge_pve_users(dry_run=True)

# Network operations  
manager.networks.ensure_user_vnet("john.doe")

# High-level operations
manager.setup_user_range("john.doe")
```

### CLI Examples
```bash
# VM management
python range_cli.py vm nuke --pattern ".*test.*"
python range_cli.py vm power --pattern ".*windows.*" --action start

# User management
python range_cli.py user create testuser --password secret
python range_cli.py user purge --dry-run

# Range setup
python range_cli.py range setup john.doe
python range_cli.py range setup-all --skip-admins
```

## Code Quality Standards

The project uses modern Python practices:
- **Type hints** for better IDE support and documentation
- **Comprehensive docstrings** for all functions
- **Modern project structure** with `pyproject.toml`
- **Code formatting** with Black (88 character line length)
- **Linting** with flake8
- **Testing** with pytest (when applicable)

### Development Tools
```bash
# Install development dependencies
pip install -e ".[dev]"

# Code formatting
black .

# Linting
flake8 .

# Type checking
mypy .
```

## File Structure

```
├── .github/                 # GitHub workflows and documentation
├── scripts/                 # PowerShell scripts for AD operations
├── static/                  # Web interface static files
├── templates/               # Flask HTML templates
├── rangemgr.py             # Core library with all functionality (~600 lines)
├── range_cli.py            # Command-line interface (~350 lines)
├── web.py                  # Flask web application
├── tui.py                  # Interactive text-based UI
├── dev.py                  # Development helper script
├── secrets.toml.example    # Configuration template
├── requirements.txt        # Python dependencies
├── pyproject.toml          # Modern Python project configuration
├── MIGRATION.md            # Scripts consolidation documentation
└── README.md               # Project documentation
```

## Migration Notes

This project recently consolidated individual scripts into a unified library:
- **Before**: 7 individual scripts with ~608 lines and significant duplication
- **After**: Unified `rangemgr.py` library with `range_cli.py` interface (~1100 lines, no duplication)

Benefits of consolidation:
- Single source of truth for all operations
- Consistent error handling and logging
- Better type hints and documentation
- Dry-run support across all operations

## Testing

The system includes several validation mechanisms:
- `python dev.py check` - Development environment validation
- Syntax checking with `py_compile`
- Import validation for core modules
- Health check endpoint for runtime status

## Troubleshooting

### Common Issues
1. **Import errors**: Ensure all dependencies are installed via `pip install -r requirements.txt`
2. **Configuration errors**: Verify `secrets.toml` file exists and has correct Proxmox credentials
3. **Connection issues**: Check network connectivity to Proxmox host and SSL settings
4. **Permission errors**: Ensure Proxmox user has appropriate administrative privileges

### Debugging
- Enable debug logging by setting log level to DEBUG in web.py or rangemgr.py
- Use `--dry-run` flag with CLI operations to test without making changes
- Check `range.log` file for detailed operation logs
- Use health check endpoint (`/health`) to verify system status

## Contributing

When contributing to this project:
1. Follow existing code style (Black formatting, type hints, docstrings)
2. **Always run black linter before pushing to any pull request**: `black .`
3. Ensure all Python files compile without syntax errors
4. Test changes with both web interface and CLI tools
5. Update documentation for new features or significant changes
6. Use descriptive commit messages and maintain clean git history

### Pre-commit Requirements
Before pushing any changes to a pull request in process:
```bash
# Format code with black
black .

# Verify formatting compliance
black --check .

# Check syntax
python -m py_compile *.py
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Contact

- **Organization**: champcybersec
- **Email**: range@champcybersec.org
- **Repository**: https://github.com/champcybersec/range