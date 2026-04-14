"""
Proxmox Range Management Web Interface

This Flask application provides a web interface for managing Proxmox VMs
in a competitive cyber training environment. It allows administrators to:
- Clone VMs for users from template images
- Manage user permissions on VMs
- Integrate with Active Directory for user authentication

The application connects to a Proxmox cluster and manages VMs, pools,
and network configurations for training scenarios.
"""

from flask import Flask, render_template, request, make_response, redirect
from proxmoxer import ProxmoxAPI
import json
import os
import random
import re
import string
import tomli
import logging
from typing import Dict, Any, Optional
from rangemgr import (
    RangeManager,
    load_secrets,
    get_proxmox_client,
    load_vmids,
    build_vm_clone_name,
    build_resource_prefix,
    load_infra_config,
)

# Configure logging for development and debugging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("range.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


# Load secrets using the unified function from rangemgr
logger.info("Loading configuration using rangemgr")

try:
    # Load configuration secrets using rangemgr
    secrets = load_secrets()
    range_manager = RangeManager(secrets)
except FileNotFoundError:
    logger.error(
        "Configuration file 'secrets.toml' not found. Copy secrets.toml.example and configure."
    )
    raise
except Exception as e:
    logger.error(f"Failed to load configuration: {e}")
    raise

# Proxmox connection configuration
PROXMOX_HOST = secrets["proxmox"]["host"]  # e.g. 192.168.3.236
PROXMOX_USER = secrets["proxmox"]["user"]  # e.g. root@pam
PROXMOX_PASSWORD = secrets["proxmox"]["password"]
PROXMOX_VERIFY_SSL = secrets["proxmox"].get("verify_ssl", False)
PROXMOX_NODE = secrets["proxmox"].get("node", "pve")

# Web application authentication
SUPER_SECRET = secrets.get("web", {}).get("admin_password", "changeme")
AUTHK = "yup"  # Authentication cookie value

SELF_SERVICE_CLUB = "TEST"

# ---------------------------------------------------------------------------
# Runtime state — persisted to a small JSON file so it survives restarts.
# Stores: active_vmid (the template the admin wants users to clone tonight).
# ---------------------------------------------------------------------------
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "range_state.json")


def _load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        logger.warning("Could not persist state to %s: %s", STATE_FILE, e)


_state: dict = _load_state()


def get_vnet_for_user(
    _proxmox: ProxmoxAPI, username: str, club: Optional[str] = None
) -> Optional[str]:
    """
    Get the virtual network (vnet) assigned to a specific user.

    Uses the rangemgr NetworkManager for consistency.

    Args:
        proxmox: Authenticated ProxmoxAPI client (kept for compatibility)
        username: Username to look up network for
        club: Optional namespace/club identifier

    Returns:
        The vnet name if found, None otherwise
    """
    return range_manager.networks.get_vnet_for_user(username, club=club)


def get_proxmox() -> ProxmoxAPI:
    """
    Create and return an authenticated ProxmoxAPI client.

    Uses the rangemgr get_proxmox_client function for consistency.

    Returns:
        Configured ProxmoxAPI client instance

    Raises:
        Exception: If connection to Proxmox fails
    """
    return get_proxmox_client(secrets)


@app.route("/health")
def health_check():
    """
    Health check endpoint for monitoring and load balancers.

    Returns:
        JSON response with system status
    """
    try:
        # Test basic Proxmox connectivity
        prox = get_proxmox()
        version = prox.version.get()

        return {
            "status": "healthy",
            "proxmox_connected": True,
            "proxmox_version": version.get("version", "unknown"),
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "proxmox_connected": False, "error": str(e)}, 503


@app.route("/")
def home():
    """
    Home page with navigation links.

    Returns:
        Rendered HTML page with navigation links
    """
    return render_template(
        "page.html",
        content=(
            "<h2>Welcome</h2>"
            "<p><a href='/register'>Get your VM &rarr;</a></p>"
            "<p><small><a href='/clone'>AD self-service clone</a> &nbsp;|&nbsp; <a href='/login'>Admin login</a></small></p>"
        ),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Admin login page and authentication handler.

    GET: Display login form
    POST: Process login credentials

    Returns:
        GET: Login form page
        POST: Redirect to admin area or back to login with error
    """
    if request.method == "GET":
        if request.cookies.get("flash"):
            flash = request.cookies.get("flash")
            pc = render_template("login.html", flash=flash)
            resp = make_response(render_template("page.html", content=pc))
            resp.set_cookie("flash", "", expires=0)
            return resp
        return render_template(
            "page.html", content=render_template("login.html", flash=None)
        )
    else:
        if request.form.get("password") == SUPER_SECRET:
            resp = make_response(redirect(request.args.get("next", "/admin")))
            resp.set_cookie("sk-lol", AUTHK)
            return resp
        else:
            resp = make_response(redirect("/login"))
            resp.set_cookie("flash", "Incorrect Password")
            return resp


@app.route("/logout")
def logout():
    """
    Logout handler - clears authentication cookie.

    Returns:
        Redirect to specified page or home
    """
    resp = make_response(redirect(request.args.get("next", "/")))
    resp.set_cookie("sk-lol", "", expires=0)
    return resp


def _random_suffix(length: int = 6) -> str:
    """Generate a random alphanumeric suffix for auto-generated usernames."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _random_password(length: int = 12) -> str:
    """Generate a random password with letters, digits, and a few symbols."""
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choices(chars, k=length))


@app.route("/admin")
def adm():
    """
    Admin dashboard page.

    Requires authentication via login cookie.

    Returns:
        Admin page with Proxmox connection info, or redirect to login
    """
    if request.cookies.get("sk-lol") == AUTHK:
        try:
            vm_templates = load_vmids()
        except Exception:
            vm_templates = {}
        return render_template(
            "admin.html",
            prox_login=PROXMOX_USER,
            vm_templates=vm_templates,
            active_vmid=_state.get("active_vmid"),
            active_club=_state.get("active_club", "TEST"),
        )
    else:
        return redirect("/login?next=/admin")


@app.route("/ensure", methods=["POST"])
def ensure():
    """
    Validate that AD realm users exist for given usernames.

    Updated endpoint that validates users exist in AD realm instead of creating PVE users.

    Expects JSON payload: {"usernames": "user1,user2,..."}

    Returns:
        Success message, error list, or redirect to login if not authenticated
    """
    if request.cookies.get("sk-lol") != AUTHK:
        return redirect("/login")
    else:
        data = request.get_json()
        usernames = data["usernames"].split(",")

        # Load range manager for user validation
        from rangemgr import RangeManager, load_secrets

        secrets = load_secrets()
        range_manager = RangeManager(secrets)

        missing_users = []
        valid_users = []

        for username in usernames:
            username = username.strip()
            if range_manager.users.validate_ad_user(username):
                valid_users.append(username)
            else:
                missing_users.append(username)

        if missing_users:
            error_msg = f"The following users do not exist in AD realm: {', '.join(missing_users)}. "
            error_msg += "Please contact an administrator to create these accounts on the domain controller."
            return error_msg, 400

        return f"All users validated in AD realm: {', '.join(valid_users)}"


@app.route("/range", methods=["POST"])
def mrange():
    """
    Bulk VM cloning endpoint for multiple users and VMs.

    Admin-only endpoint that clones specified VM templates for multiple users.
    Each user gets their own copy of each specified VM template.
    All users must exist in AD realm.

    Expects JSON payload: {
        "vmids": "101,102,103",  # Comma-separated VM template IDs
        "usernames": "user1,user2,user3"  # Comma-separated usernames
    }

    Returns:
        Success message or error string
    """
    if request.cookies.get("sk-lol") != AUTHK:
        return redirect("/login")

    vmids = [int(vm_id) for vm_id in request.get_json()["vmids"].split(",")]
    users = [u.strip() for u in request.get_json()["usernames"].split(",")]

    logger.info(f"Bulk cloning VMs {vmids} for users {users}")
    print("Cloning VMs: ", vmids)
    print("For Users: ", users)

    # Load range manager for user validation
    from rangemgr import RangeManager, load_secrets

    secrets = load_secrets()
    range_manager = RangeManager(secrets)

    # Validate all users exist in AD realm
    missing_users = []
    for user in users:
        if not range_manager.users.validate_ad_user(user):
            missing_users.append(user)

    if missing_users:
        error_msg = f"The following users do not exist in AD realm: {', '.join(missing_users)}. "
        error_msg += "Please contact an administrator to create these accounts on the domain controller."
        return error_msg, 400

    try:
        prox = get_proxmox()
        try:
            vm_templates = load_vmids()
        except Exception as exc:
            logger.debug("Unable to load VM templates: %s", exc)
            vm_templates = {}

        for user in users:
            for base_vmid in vmids:
                # Support optional club prefix in username strings (e.g., 'CCDC/jane.doe')
                club_name = None
                username_only = user
                if "/" in user:
                    club_name, username_only = user.split("/", 1)
                clone_name = build_vm_clone_name(
                    username_only,
                    base_vmid,
                    club=club_name,
                    templates=vm_templates,
                )

                # Create a clone name and ID
                new_vmid = prox.cluster.nextid.get()
                prox.nodes(PROXMOX_NODE).qemu(base_vmid).clone.post(
                    newid=new_vmid,
                    name=clone_name,
                    full=0,
                    target=PROXMOX_NODE,
                )
                # Assign Administrator to user@ad
                prox.access.acl.put(
                    path=f"/vms/{new_vmid}", users=f"{user}@ad", roles="Administrator"
                )
        return "Wahoo"
    except Exception as e:
        return str(e)


@app.route("/clone", methods=["GET", "POST"])
def clone_page():
    """
    Individual VM cloning page with AD authentication.

    GET: Display clone form with available templates
    POST: Clone selected template for the specified user

    This endpoint creates VMs for users in the AD realm and assigns them
    to user-specific pools and networks.

    Returns:
        GET: Clone form page
        POST: Success page with new VM details or error message
    """
    if request.method == "GET":
        # Load VM templates from TOML configuration
        try:
            vm_templates = load_vmids()
        except Exception as e:
            logger.error(f"Failed to load VM templates: {e}")
            vm_templates = {}

        return render_template(
            "page.html",
            content=render_template("clone.html", vm_templates=vm_templates),
        )
    raw_username = (request.form.get("username") or "").strip()
    vmid_raw = request.form.get("vmid")

    if not raw_username or not vmid_raw:
        return (
            render_template("page.html", content="<h2>Username and VMID required</h2>"),
            400,
        )

    try:
        vmid = int(vmid_raw)
    except (TypeError, ValueError):
        return (
            render_template(
                "page.html", content=f"<h2>Invalid VMID supplied: {vmid_raw}</h2>"
            ),
            400,
        )

    username_only = raw_username
    if "/" in raw_username:
        _, username_only = raw_username.split("/", 1)
    username_only = username_only.strip()

    if not username_only:
        return (
            render_template(
                "page.html",
                content="<h2>Username cannot be empty after processing namespace</h2>",
            ),
            400,
        )

    club_name = SELF_SERVICE_CLUB

    # Validate user exists in AD realm
    if not range_manager.users.validate_ad_user(username_only):
        error_msg = range_manager.users.get_ad_user_error_message(username_only)
        return (
            render_template(
                "page.html", content=f"<h2>User Validation Error</h2><p>{error_msg}</p>"
            ),
            400,
        )

    # Ensure the user's TEST club range exists before cloning
    if not range_manager.setup_user_range(username_only, club=club_name):
        logger.error(
            "Failed to set up range for %s in %s namespace", username_only, club_name
        )
        return (
            render_template(
                "page.html",
                content=(
                    "<h2>Range Setup Error</h2>"
                    f"<p>Unable to prepare the {club_name} range for {username_only}@ad."
                    " Please contact an administrator.</p>"
                ),
            ),
            500,
        )

    try:
        infra_config = load_infra_config()
        naming_config = infra_config.get("naming", {})
        pool_suffix_value = naming_config.get("pool_suffix", "-range")
        pool_suffix = "-range"
        if pool_suffix_value is not None:
            pool_suffix_str = str(pool_suffix_value).strip()
            if pool_suffix_str:
                pool_suffix = pool_suffix_str
    except Exception as exc:
        logger.error("Failed to load infrastructure configuration: %s", exc)
        pool_suffix = "-range"

    resource_prefix = build_resource_prefix(username_only, club_name)
    pool_name = f"{resource_prefix}{pool_suffix}"

    logger.info(
        "Cloning VM %s for user %s@ad within %s namespace pool %s",
        vmid,
        username_only,
        club_name,
        pool_name,
    )
    try:
        prox = get_proxmox()
        try:
            vm_templates = load_vmids()
        except Exception as exc:
            logger.debug("Unable to load VM templates: %s", exc)
            vm_templates = {}

        clone_name = build_vm_clone_name(
            username_only,
            vmid,
            club=club_name,
            templates=vm_templates,
        )

        new_vmid = prox.cluster.nextid.get()
        prox.nodes(PROXMOX_NODE).qemu(vmid).clone.post(
            newid=new_vmid,
            name=clone_name,
            full=0,
            target=PROXMOX_NODE,
            pool=pool_name,
        )

        # Configure network using user-specific vnet in TEST namespace
        vnet_name = range_manager.networks.get_vnet_for_user(
            username_only, club=club_name
        )
        if not vnet_name:
            logger.error(
                "No VNet found for %s in %s namespace after setup",
                username_only,
                club_name,
            )
            return (
                render_template(
                    "page.html",
                    content=(
                        "<h2>Networking Error</h2>"
                        f"<p>Could not locate a VNet for {username_only}@ad in the {club_name} namespace."
                        " Please contact an administrator.</p>"
                    ),
                ),
                500,
            )

        net0 = f"e1000,bridge={vnet_name}"
        prox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(net0=net0)

        # Grant Administrator role to username@ad on this VM
        prox.access.acl.put(
            path=f"/vms/{new_vmid}",
            users=f"{username_only}@ad",
            roles="PVEAdmin,Administrator",
        )

        return render_template(
            "page.html",
            content=(
                "<h2>"
                f"Cloned VMID {vmid} to {new_vmid} and granted Administrator to {username_only}@ad"
                f" in the {club_name} namespace"
                "</h2>"
                "<p>Next, log into Proxmox at "
                "<a href='https://192.168.3.236:8006' target='_blank' rel='noopener'>"
                "https://192.168.3.236:8006</a></p>"
            ),
        )
    except Exception as e:
        logger.error(
            "Failed to clone VM %s for user %s in %s namespace: %s",
            vmid,
            username_only,
            club_name,
            e,
        )
        return render_template("page.html", content=f"<h2>Error: {str(e)}</h2>"), 500


@app.route("/admin/set-template", methods=["POST"])
def set_template():
    """
    Admin endpoint to set the active event config: VM template + club namespace.

    Expects JSON: {"vmid": 210, "club": "NECCDC"}
    "club" defaults to "TEST" if omitted or blank — pools are always namespaced.

    Returns:
        JSON confirmation with active vmid, label, and club.
    """
    if request.cookies.get("sk-lol") != AUTHK:
        return {"error": "Unauthorized"}, 401

    data = request.get_json() or {}
    try:
        vmid = int(data["vmid"])
    except (KeyError, TypeError, ValueError):
        return {"error": "vmid must be an integer"}, 400

    club = (data.get("club") or "").strip().upper() or "TEST"

    _state["active_vmid"] = vmid
    _state["active_club"] = club
    _save_state(_state)
    logger.info("Event config set: VMID=%s club=%s", vmid, club)

    try:
        vm_templates = load_vmids()
        label = vm_templates.get(str(vmid), f"VMID {vmid}")
    except Exception:
        label = f"VMID {vmid}"

    return {"active_vmid": vmid, "label": label, "club": club}


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Self-service registration page for non-AD users.

    Users pick their own username and password. The system creates a PVE realm
    account, a dedicated pool, and a clone of the admin-configured template VM,
    then grants the new user full access to both.

    GET:  Show registration form (includes active template name).
    POST: Create account + VM, show credentials and login link.
    """
    try:
        vm_templates = load_vmids()
    except Exception:
        vm_templates = {}

    active_vmid = _state.get("active_vmid")
    if not active_vmid:
        return render_template(
            "page.html",
            content=(
                "<h2>Registration not available</h2>"
                "<p>No VM template has been configured yet. Please ask an admin to set one.</p>"
            ),
        ), 503

    template_label = vm_templates.get(str(active_vmid), f"VMID {active_vmid}")

    if request.method == "GET":
        return render_template(
            "page.html",
            content=render_template(
                "register.html",
                template_label=template_label,
                active_vmid=active_vmid,
            ),
        )

    # --- POST: create user + VM ---
    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""

    # Basic validation
    if not username:
        return _register_error("Username is required.", template_label, active_vmid)
    if not re.match(r'^[a-z0-9][a-z0-9._-]{1,30}$', username):
        return _register_error(
            "Username must be 2–31 characters, start with a letter or digit, "
            "and contain only letters, digits, dots, hyphens, or underscores.",
            template_label, active_vmid,
        )
    if len(password) < 8:
        return _register_error("Password must be at least 8 characters.", template_label, active_vmid)
    if password != confirm:
        return _register_error("Passwords do not match.", template_label, active_vmid)

    userid = f"{username}@pve"
    if range_manager.users.user_exists(userid):
        return _register_error(
            f"Username '{username}' is already taken. Please choose another.",
            template_label, active_vmid,
        )
    if range_manager.users.validate_ad_user(username):
        return _register_error(
            f"'{username}' already exists as a domain account — use the "
            "<a href='/clone'>AD clone page</a> instead, or choose a different username.",
            template_label, active_vmid,
        )

    # Create PVE user
    if not range_manager.users.create_pve_user(username, password):
        return _register_error("Could not create account — please contact an admin.", template_label, active_vmid), 500

    # Create pool and clone VM
    club = _state.get("active_club") or "TEST"
    resource_prefix = build_resource_prefix(username, club)
    pool_name = f"{resource_prefix}-range"
    try:
        infra_config = load_infra_config()
        infranet_bridge = infra_config.get("networking", {}).get("infranet_bridge", "INFRANET")
    except Exception:
        infranet_bridge = "INFRANET"

    if not range_manager.pools.ensure_pool(pool_name):
        return _register_error("Could not create resource pool — please contact an admin.", template_label, active_vmid), 500

    try:
        prox = get_proxmox()
        prox.access.acl.put(path=f"/pool/{pool_name}", users=userid, roles="Administrator,PVEAdmin")

        clone_name = build_vm_clone_name(username, active_vmid, club=club, templates=vm_templates)
        new_vmid = prox.cluster.nextid.get()
        prox.nodes(PROXMOX_NODE).qemu(active_vmid).clone.post(
            newid=new_vmid,
            name=clone_name,
            full=0,
            target=PROXMOX_NODE,
            pool=pool_name,
        )
        prox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(
            net0=f"e1000,bridge={infranet_bridge}"
        )
        prox.access.acl.put(path=f"/vms/{new_vmid}", users=userid, roles="Administrator,PVEAdmin")
        logger.info("Self-service: provisioned %s (vmid %s) for %s", clone_name, new_vmid, userid)
    except Exception as e:
        logger.error("Self-service clone failed for %s: %s", userid, e)
        return _register_error(f"VM clone failed: {e} — please contact an admin.", template_label, active_vmid), 500

    return render_template(
        "page.html",
        content=render_template(
            "register_success.html",
            username=username,
            new_vmid=new_vmid,
            template_label=template_label,
            login_url=f"https://{PROXMOX_HOST}:8006",
        ),
    )


def _register_error(message: str, template_label: str, active_vmid: int):
    return render_template(
        "page.html",
        content=render_template(
            "register.html",
            template_label=template_label,
            active_vmid=active_vmid,
            error=message,
        ),
    ), 400


@app.route("/provision", methods=["POST"])
def provision():
    """
    Provision one or more PVE-realm users with a cloned VM each.

    Admin-only endpoint. Creates users directly in the Proxmox PVE realm (no AD
    required), creates a pool per user, clones the requested VM template, places
    the VM on the shared INFRANET bridge, and grants the new user Administrator
    access to their pool and VM.

    Expects JSON payload:
        {
            "vmid": 210,            # template VMID to clone (required)
            "count": 5,             # number of accounts to create (default 1)
            "prefix": "user",       # username prefix for bulk auto-generation
            "username": "alice",    # override for single-user provisioning
            "password": "s3cr3t"    # override for single-user provisioning
        }

    Returns:
        JSON: {"results": [{"username": ..., "password": ..., "vmid": ..., "login_url": ...}, ...]}
    """
    if request.cookies.get("sk-lol") != AUTHK:
        return {"error": "Unauthorized"}, 401

    data = request.get_json() or {}

    try:
        template_vmid = int(data.get("vmid", 0))
    except (TypeError, ValueError):
        return {"error": "Invalid vmid"}, 400

    if not template_vmid:
        return {"error": "vmid is required"}, 400

    try:
        count = max(1, min(50, int(data.get("count", 1))))
    except (TypeError, ValueError):
        count = 1

    prefix = (data.get("prefix") or "user").strip() or "user"

    try:
        vm_templates = load_vmids()
    except Exception:
        vm_templates = {}

    try:
        infra_config = load_infra_config()
        infranet_bridge = infra_config.get("networking", {}).get("infranet_bridge", "INFRANET")
    except Exception:
        infranet_bridge = "INFRANET"

    prox = get_proxmox()
    results = []

    for _ in range(count):
        if count == 1 and data.get("username"):
            username = data["username"].strip()
        else:
            username = f"{prefix}-{_random_suffix()}"

        if count == 1 and data.get("password"):
            password = data["password"].strip()
        else:
            password = _random_password()

        userid = f"{username}@pve"

        if range_manager.users.user_exists(userid):
            results.append({"username": username, "error": "User already exists"})
            continue

        if not range_manager.users.create_pve_user(username, password):
            results.append({"username": username, "error": "Failed to create PVE user"})
            continue

        provision_club = _state.get("active_club") or "TEST"
        pool_name = f"{build_resource_prefix(username, provision_club)}-range"
        if not range_manager.pools.ensure_pool(pool_name):
            results.append({"username": username, "password": password, "error": "Failed to create pool"})
            continue

        try:
            prox.access.acl.put(
                path=f"/pool/{pool_name}", users=userid, roles="Administrator,PVEAdmin"
            )
        except Exception as e:
            logger.warning("Failed to set pool ACL for %s: %s", userid, e)

        try:
            clone_name = build_vm_clone_name(username, template_vmid, club=provision_club, templates=vm_templates)
            new_vmid = prox.cluster.nextid.get()
            prox.nodes(PROXMOX_NODE).qemu(template_vmid).clone.post(
                newid=new_vmid,
                name=clone_name,
                full=0,
                target=PROXMOX_NODE,
                pool=pool_name,
            )
            prox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(
                net0=f"e1000,bridge={infranet_bridge}"
            )
            prox.access.acl.put(
                path=f"/vms/{new_vmid}", users=userid, roles="Administrator,PVEAdmin"
            )
            logger.info("Provisioned %s (vmid %s) for %s", clone_name, new_vmid, userid)
            results.append({
                "username": username,
                "password": password,
                "vmid": new_vmid,
                "login_url": f"https://{PROXMOX_HOST}:8006",
            })
        except Exception as e:
            logger.error("Failed to clone VM %s for %s: %s", template_vmid, userid, e)
            results.append({
                "username": username,
                "password": password,
                "error": f"Clone failed: {e}",
            })

    return {"results": results}


@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors with custom page."""
    return (
        render_template(
            "page.html",
            content="<h2>Page not found. Please check spelling and try again</h2>",
        ),
        404,
    )


@app.errorhandler(500)
def uhoh_yikes(e):
    """Handle 500 errors with custom page showing error details."""
    return (
        render_template(
            "page.html",
            content=f"<h2>Internal Server Error</h2><br/><pre><code>{str(e)}</code></pre>",
        ),
        500,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7878, debug=True)
