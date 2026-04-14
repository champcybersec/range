# ccdc-range — Agent Instructions

## Pool naming: always use a namespace prefix

Proxmox pools in this project **must never be created at the top level** (e.g. `alice-range` is wrong).
Every pool must be prefixed with a club/event namespace: `CLUB/username-range`.

- Use `build_resource_prefix(username, club)` which returns `"CLUB/username"`, then append the pool suffix: `f"{prefix}-range"`.
- If no club is known, default to `"TEST"` — never omit the prefix entirely.
- This applies everywhere a pool is created: `/register`, `/provision`, `setup_user_range`, CLI `range setup`, etc.

**Correct:**   `NECCDC/alice-range`, `TEST/bob-range`
**Wrong:**     `alice-range`, `bob-range`

The `ensure_pool` helper in `PoolManager` already handles creating the parent pool (`NECCDC`) automatically before creating the child (`NECCDC/alice-range`), so there is no extra work needed.

## Realms

- AD users: `username@ad` — validated via `users.validate_ad_user(username)`
- PVE users: `username@pve` — created via `users.create_pve_user(username, password)`
- When registering a PVE user, also check that `username@ad` does not already exist to avoid duplicate identities across realms.

## Active event config (`range_state.json`)

Runtime state (active VMID + club namespace) is persisted in `range_state.json` alongside `secrets.toml`.
Read it via the `_state` dict in `web.py`; update it through the `/admin/set-template` endpoint.
Never hardcode a VMID or club name in route logic — always read from `_state`.

## Self-service registration flow (`/register`)

1. Admin sets active VMID + club in `/admin` → saved to `range_state.json`
2. User visits `/register`, picks username + password
3. System: creates `username@pve`, creates `CLUB/username-range` pool, clones template VM, puts VM on INFRANET bridge, grants `Administrator,PVEAdmin` on pool and VM
4. User logs into Proxmox directly with `username@pve` credentials — no admin distribution needed

## Key files

- `rangemgr.py` — all Proxmox logic (VMs, users, networks, pools)
- `web.py` — Flask routes; reads `_state` for active event config
- `range_state.json` — runtime state (gitignored, created at runtime)
- `secrets.toml` — credentials (gitignored)
- `infra.toml` — infrastructure naming/networking config
- `vmids.toml` — VM template definitions
