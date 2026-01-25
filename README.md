# Proxmox Range Management

Small-but-mighty toolkit for running competition “ranges” on Proxmox. It lets staff spin up user pools, clone VMs, wire SDN VNets, and clean up leftovers without touching the Proxmox UI.

## TL;DR
- **Everything in one place**: `rangemgr.py` powers the CLI, web UI, and TUI.
- **Multi-club aware**: resources use the `CLUB/username-range` pattern so teams stay isolated.
- **Safe destructive ops**: dry-run modes and automatic `prod` / `infra` safeguards guard your cluster.
- **Works with AD**: validates `@ad` users before building their range.

## Quick Start
1. Create a virtualenv, then `pip install -r requirements.txt`.
2. Copy `secrets.toml.example` to `secrets.toml` and fill in your Proxmox + AD details.
3. Run `python range_cli.py --help` to browse commands.

## Common CLI One-Liners
```bash
# VM management
python range_cli.py vm list --pattern ".*range.*"
python range_cli.py vm nuke ".*-wk." --dry-run

# Network management
python range_cli.py network ensure-user matt.compton --club CCDC
python range_cli.py network ensure-all --club PRAC

# Pool lifecycle
python range_cli.py pool nuke ".*-range" --dry-run

# Full range provisioning
python range_cli.py range setup matt.compton --base-vmid 150 --club CCDC
python range_cli.py range setup-all --skip-admins --club PRAC
```

## Naming & Multi-Club Support
- Pools and VNets still derive from the `CLUB/username` resource prefix.
- Gateway VMs now normalize to `club-range-gateway-username` (legacy `range-vyos` names remain detectable).
- Template clones adopt `first.last-club-template-name`, making it easy to bulk delete by club or template.
- Legacy names (`username-range`, `CLUB-username-range`) still resolve, but new assets adopt the slash style automatically.

## Other Interfaces
- `web.py`: lightweight Flask UI for quick clones.
- `tui.py`: menu-driven workflows if you prefer arrow keys.
- `test_network_manager.py`: unit coverage for the matching logic that protects VNets.

## Need the Deep Dive?
All detailed docs, history, migration notes, and contributor guidance live in `.github/copilot-instructions.md`.
