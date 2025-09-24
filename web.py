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
import os
import random
import tomli
import logging
from typing import Dict, Any, Optional
from rangemgr import RangeManager, load_secrets, get_proxmox_client

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
PROXMOX_VERIFY_SSL = secrets["proxmox"].get("verify_ssl", True)
PROXMOX_NODE = secrets["proxmox"].get("node", "pve")

# Web application authentication
SUPER_SECRET = secrets.get("web", {}).get("admin_password", "changeme")
AUTHK = "yup"  # Authentication cookie value


def get_vnet_for_user(proxmox: ProxmoxAPI, username: str) -> Optional[str]:
    """
    Get the virtual network (vnet) assigned to a specific user.

    Uses the rangemgr NetworkManager for consistency.

    Args:
        proxmox: Authenticated ProxmoxAPI client (kept for compatibility)
        username: Username to look up network for

    Returns:
        The vnet name if found, None otherwise
    """
    return range_manager.networks.get_vnet_for_user(username)


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
        content="<h2>Home</h2><p><a href='/clone'>Clone VM</a><br/><br/><a href='/login'>Admin Login</a>",
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


@app.route("/admin")
def adm():
    """
    Admin dashboard page.

    Requires authentication via login cookie.

    Returns:
        Admin page with Proxmox connection info, or redirect to login
    """
    if request.cookies.get("sk-lol") == AUTHK:
        return render_template("admin.html", prox_login=PROXMOX_USER)
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
        for user in users:
            for base_vmid in vmids:
                # Create a clone name and ID
                new_vmid = prox.cluster.nextid.get()
                name = f"{user}-range-{base_vmid}"
                prox.nodes(PROXMOX_NODE).qemu(base_vmid).clone.post(
                    newid=new_vmid,
                    name=name,
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
        from rangemgr import load_vmids
        try:
            vm_templates = load_vmids()
        except Exception as e:
            logger.error(f"Failed to load VM templates: {e}")
            vm_templates = {}
        
        return render_template("page.html", content=render_template("clone.html", vm_templates=vm_templates))
    username = request.form.get("username").strip()
    vmid = int(request.form.get("vmid"))
    if not username or not vmid:
        return (
            render_template("page.html", content="<h2>Username and VMID required</h2>"),
            400,
        )

    # Load range manager for user validation
    from rangemgr import RangeManager, load_secrets

    secrets = load_secrets()
    range_manager = RangeManager(secrets)

    # Validate user exists in AD realm
    if not range_manager.users.validate_ad_user(username):
        error_msg = range_manager.users.get_ad_user_error_message(username)
        return (
            render_template(
                "page.html", content=f"<h2>User Validation Error</h2><p>{error_msg}</p>"
            ),
            400,
        )

    logger.info(f"Cloning VM {vmid} for user {username}@ad")
    try:
        prox = get_proxmox()
        new_vmid = prox.cluster.nextid.get()
        prox.nodes(PROXMOX_NODE).qemu(vmid).clone.post(
            newid=new_vmid,
            name=f"{username}-range-wk4-{vmid}",
            full=0,
            target=PROXMOX_NODE,
            pool=f"{username}-range",
        )

        # Configure network using user-specific vnet
        net0 = f"e1000,bridge={get_vnet_for_user(prox, username)}"
        prox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(net0=net0)

        # Grant Administrator role to username@ad on this VM
        prox.access.acl.put(
            path=f"/vms/{new_vmid}",
            users=f"{username}@ad",
            roles="PVEAdmin,Administrator",
        )

        return render_template(
            "page.html",
            content=f"<h2>Cloned VMID {vmid} to {new_vmid} and granted Administrator to {username}@ad</h2><p>Next, log into Proxmox at <a href='https://192.168.3.236:8006' target='_blank' rel='noopener'>https://192.168.3.236:8006</a></p>",
        )
    except Exception as e:
        logger.error(f"Failed to clone VM {vmid} for user {username}: {e}")
        return render_template("page.html", content=f"<h2>Error: {str(e)}</h2>"), 500


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
