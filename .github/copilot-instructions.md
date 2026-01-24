# Proxmox Range Management — Copilot Playbook

## 1. Guardrails (Read First)
- **Never overwrite or delete `README.md`.** It carries the human-facing TL;DR.
- Keep resource naming in the `CLUB/username-range` format unless explicitly told otherwise.
- Treat `prod` and `infra` pools as immutable unless the request states otherwise.
- Preserve existing dry-run behaviour when extending destructive commands.

## 2. What This Repository Does
Python tooling for competition “ranges” hosted on Proxmox. The core library (`rangemgr.py`) exposes VM, pool, user, and SDN helpers that power:
- `range_cli.py` – the primary operational interface.
- `web.py` – a Flask admin/self-service portal.
- `tui.py` – a lightweight curses-style navigator.

The system validates AD users, clones VyOS gateways plus optional workload VMs, wires them into SDN VNets, assigns ACLs, and can tear everything back down.

## 3. Resource Naming & Compatibility
- New assets follow: `CLUB/username-range` (pools), `CLUB/username-range-vyos` (gateways), `CLUB/username-range-{template}` (workload clones), and VNets tagged with alias `CLUB/username`.
- `rangemgr.NetworkManager` continues to recognise legacy aliases (`username`, `CLUB-username`) so existing deployments keep working.
- Pool clean-up (`pool nuke`) automatically ignores anything containing `prod` or `infra`.

## 4. Architecture Cheat Sheet
| Component | Responsibility | Key Notes |
|-----------|----------------|-----------|
| `RangeManager` | High-level orchestration | Wraps VM, user, network, pool managers |
| `VMManager` | VM lifecycle operations | Pattern-based power/nuke helpers, MAC preservation |
| `UserManager` | Proxmox user CRUD + AD validation | Works primarily against the `ad` realm |
| `NetworkManager` | SDN VNet management | Ensures/creates VNets, reuses unassigned RN ranges |
| `PoolManager` | Pool CRUD | New pattern-aware nuke helper with safeguards |

Supporting modules: `web.py`, `tui.py`, `range_cli.py`, `dev.py`, configuration in `secrets.toml`, `infra.toml`, and `vmids.toml`.

## 5. Workflow Highlights
### Provisioning a Range
1. Validate `username@ad`.
2. Ensure pool `CLUB/username-range`.
3. Ensure/assign VNet alias `CLUB/username`.
4. Clone VyOS gateway (`vyos_base_vmid`), attach infranet + user VNet, grant ACLs.
5. Optionally clone workload templates (`--vmids`) into the same pool and bridge.

### Cleaning Up
- `range_cli.py pool nuke ".*-range"` → deletes pools except protected ones (dry-run available).
- `range_cli.py vm nuke "pattern"` → stops + deletes matching VMs.
- `range_cli.py network ensure-user USER --club CLUB` → idempotent; reuses unassigned VNets or creates new ones starting at `RN37`.

### Multi-Club Support
- Pass `--club CLUB` to `network ensure-*` and `range setup*` commands.
- Legacy assets are detected and logged, but new aliases adopt the slash format.

## 6. Development & Testing Notes
1. Create a virtualenv and install `requirements.txt`.
2. Copy `secrets.toml.example` → `secrets.toml`; adjust Proxmox credentials, node, and AD details.
3. `python range_cli.py --help` to explore operations.
4. `python -m unittest tests.test_network_manager` exercises username/alias logic and pool safety. (When running locally, install `proxmoxer`; the sandbox environment here lacks it.)
5. `dev.py` includes helper checks (`python dev.py check`) for linting/setup.

## 7. Migration & History (from former MIGRATION.md/CHANGELOG.md)
- Legacy scripts (`setup_range.py`, `nuke_gw.py`, etc.) were consolidated into `rangemgr.py` + `range_cli.py`, yielding ~1100 lines of reusable code (down from 7 duplicated scripts).
- Web and TUI layers were refactored to call into the same library, ensuring consistent logging, error handling, and dry-run semantics.
- Project modernised with `pyproject.toml`, type hints, structured logging, `dev.py` helpers, and richer documentation.
- Username/VNet matching was hardened (case-insensitive, trimmed aliases) to stop duplicate VNets and incorrect assignments (see `tests/test_network_manager.py` for coverage).

## 8. Troubleshooting Quick Hits
- **ImportError: proxmoxer** – install `proxmoxer` in your active environment.
- **Auth issues** – confirm `secrets.toml` has correct host/user/password and the host string omits `/api2/json`.
- **Range setup fails** – check AD validation logs and ensure the user exists; RangeManager aborts early if AD lookup fails.
- **Network alias mismatch** – logs report “legacy alias” when older naming is detected; rerun ensure commands to normalise.

## 9. Extending the Project
- Extend CLI by wiring new subcommands in `range_cli.py`, then add corresponding helper methods inside `RangeManager`.
- Surface new operations in the web or TUI layers by reusing `RangeManager` helpers—keep business logic out of UI code.
- Add unit coverage in `tests/test_network_manager.py` (or create new modules) when touching matching logic or pool safeguards.

## 10. When In Doubt
- Keep human documentation in `README.md`; anything more detailed belongs here.
- Cross-check naming helper `build_resource_prefix()` whenever introducing new resource types.
- Prefer dry-run or explicit confirmation flags for destructive actions.
- Log meaningful messages—operators rely on log output when running bulk jobs.
