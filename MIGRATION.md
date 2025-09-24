# Scripts Migration Guide

This document outlines the consolidation of individual scripts into the unified `rangemgr.py` library and `range_cli.py` tool.

## Script Consolidation Summary

### Before: Individual Scripts
The `scripts/` directory contained these individual Python scripts:

| Script | Purpose | Lines |
|--------|---------|-------|
| `nuke_gw.py` | Delete gateway VMs ending in `-range-gw` | 31 |
| `nuke_by_name.py` | Delete VMs matching a pattern | 38 |
| `set_power_by_name.py` | Start/stop VMs by pattern | 48 |
| `setup_range.py` | Set up complete ranges for users | 169 |
| `purge_pve_users.py` | Delete all @pve realm users | 119 |
| `cleanup_pve_user.py` | Clean up users based on CSV | 170 |
| `nuke_vnet.py` | Delete VNets from file | 33 |

**Total: ~608 lines of code with significant duplication**

### After: Unified Module + CLI

| File | Purpose | Lines |
|------|---------|-------|
| `rangemgr.py` | Unified library with all functionality | ~600 |
| `range_cli.py` | Command-line interface | ~350 |
| `tui.py` (updated) | Simplified TUI using rangemgr | ~150 |
| `web.py` (updated) | Web interface using rangemgr | (minimal changes) |

**Total: ~1100 lines with no duplication and better organization**

## Functionality Mapping

### VM Operations
```bash
# Before: Multiple scripts
python scripts/nuke_gw.py
python scripts/nuke_by_name.py "pattern"
python scripts/set_power_by_name.py start "pattern"

# After: Unified CLI
python range_cli.py vm nuke-gw
python range_cli.py vm nuke "pattern"
python range_cli.py vm power start "pattern"
```

### User Operations
```bash
# Before: Multiple scripts
python scripts/purge_pve_users.py --dry-run
python scripts/cleanup_pve_user.py --csv users.csv

# After: Unified CLI
python range_cli.py user purge-pve --dry-run
python range_cli.py user bulk-create users.csv
```

### Network Operations
```bash
# Before: Individual operations in scripts
# VNet management was embedded in setup_range.py and nuke_vnet.py

# After: Dedicated network commands
python range_cli.py network list
python range_cli.py network ensure-user john.doe
python range_cli.py network ensure-all
```

### Range Setup
```bash
# Before: Complex script
python scripts/setup_range.py

# After: High-level commands
python range_cli.py range setup john.doe
python range_cli.py range setup-all --skip-admins
```

## Benefits of Consolidation

### 1. Code Reuse
- Single `load_secrets()` function instead of 7 copies
- Unified ProxmoxAPI client creation
- Shared error handling patterns
- Common logging configuration

### 2. Consistency
- All operations use the same connection patterns  
- Standardized error messages and logging
- Consistent command-line argument parsing
- Unified configuration handling

### 3. Maintainability
- Changes to core functionality only need to be made once
- Better type hints and documentation
- Clearer separation of concerns
- Easier testing and debugging

### 4. User Experience
- Single CLI tool instead of remembering multiple scripts
- Consistent help documentation
- Better error messages
- Dry-run support across all operations

## Library Usage

The `rangemgr.py` module can be imported for custom automation:

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

## Migration Timeline

1. ✅ **Phase 1**: Create `rangemgr.py` with all consolidated functionality
2. ✅ **Phase 2**: Create `range_cli.py` unified command-line interface
3. ✅ **Phase 3**: Update `web.py` and `tui.py` to use rangemgr
4. ✅ **Phase 4**: Update documentation and examples
5. ✅ **Phase 5**: Deprecate individual scripts (keep for compatibility)
6. ✅ **Phase 6**: Remove individual scripts after transition period

## Migration Complete

All individual Python scripts have been successfully removed from the `scripts/` directory. The `Create-RangeUsers.ps1` PowerShell script has been preserved as it provides Active Directory functionality not covered by the Python CLI.

All functionality previously available in individual scripts is now accessible through the unified `range_cli.py` command-line interface with enhanced features such as dry-run support and better error handling.