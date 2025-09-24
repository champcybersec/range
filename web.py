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

# Configure logging for development and debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('range.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


def load_secrets() -> Dict[str, Any]:
    """
    Load configuration secrets from secrets.toml file.
    
    Returns:
        Dict containing configuration sections for proxmox, web, etc.
        
    Raises:
        FileNotFoundError: If secrets.toml file is not found
        tomli.TOMLDecodeError: If the TOML file is malformed
    """
    secrets_path = os.path.join(os.path.dirname(__file__), "secrets.toml")
    logger.info(f"Loading secrets from {secrets_path}")
    with open(secrets_path, "rb") as f:
        return tomli.load(f)

# Load configuration secrets
secrets = load_secrets()

# Proxmox connection configuration
PROXMOX_HOST = secrets["proxmox"]["host"]  # e.g. 192.168.3.236
PROXMOX_USER = secrets["proxmox"]["user"]  # e.g. root@pam
PROXMOX_PASSWORD = secrets["proxmox"]["password"]
PROXMOX_VERIFY_SSL = secrets["proxmox"].get("verify_ssl", True)
PROXMOX_NODE = secrets["proxmox"].get("node", "pve")

# Web application authentication
SUPER_SECRET = secrets.get("web", {}).get("admin_password", "changeme")
AUTHK = "yup"  # Authentication cookie value

# Default password for newly created PVE users (legacy support)
DEFAULT_USER_PASSWORD = secrets.get("web", {}).get("default_user_password", "ChangeMe123!")


def get_vnet_for_user(proxmox: ProxmoxAPI, username: str) -> Optional[str]:
    """
    Get the virtual network (vnet) assigned to a specific user.
    
    Args:
        proxmox: Authenticated ProxmoxAPI client
        username: Username to look up network for
        
    Returns:
        The vnet name if found, None otherwise
    """
    vnets = proxmox.cluster.sdn.vnets.get()
    for vnet in vnets:
        if vnet.get("alias") == username:
            return vnet.get("vnet")
    return None


def get_proxmox() -> ProxmoxAPI:
    """
    Create and return an authenticated ProxmoxAPI client.
    
    Returns:
        Configured ProxmoxAPI client instance
    """
    logger.debug(f"Connecting to Proxmox at {PROXMOX_HOST} as {PROXMOX_USER}")
    return ProxmoxAPI(
        PROXMOX_HOST,
        user=PROXMOX_USER,
        password=PROXMOX_PASSWORD,
        verify_ssl=PROXMOX_VERIFY_SSL,
    )


@app.route("/")
def home():
    """
    Home page with navigation links.
    
    Returns:
        Rendered HTML page with navigation links
    """
    return render_template(
        "page.html", content="<h2>Home</h2><p><a href='/clone'>Clone VM</a><br/><br/><a href='/login'>Admin Login</a>"
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
        return render_template("admin.html", prox_login=PROXMOX_USER, passw=DEFAULT_USER_PASSWORD)
    else:
        return redirect("/login?next=/admin")


@app.route("/ensure", methods=["POST"])
def ensure():
    """
    Ensure PVE local users exist for given usernames.
    
    Legacy endpoint for user management before full AD integration.
    Creates @pve realm users if they don't exist.
    
    Expects JSON payload: {"usernames": "user1,user2,..."}
    
    Returns:
        Success message or redirect to login if not authenticated
    """
    if request.cookies.get("sk-lol") != AUTHK:
        return redirect("/login")
    else:
        data = request.get_json()

        usernames = data["usernames"].split(",")

        for username in usernames:  # TODO: do we need this now that AD?
            uid = username + "@pve"
            # Create a PVE local user if missing (migration helper)
            prox = get_proxmox()
            users = prox.access.users.get()
            if not any(u.get("userid") == uid for u in users):
                prox.access.users.post(userid=uid, password=DEFAULT_USER_PASSWORD)

        return "Wahoo"


@app.route("/range", methods=["POST"])
def mrange():
    """
    Bulk VM cloning endpoint for multiple users and VMs.
    
    Admin-only endpoint that clones specified VM templates for multiple users.
    Each user gets their own copy of each specified VM template.
    
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
    users = request.get_json()["usernames"].split(",")

    logger.info(f"Bulk cloning VMs {vmids} for users {users}")
    print("Cloning VMs: ", vmids)
    print("For Users: ", users)

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
                # Assign Administrator to user@pve (legacy path)
                prox.access.acl.put(path=f"/vms/{new_vmid}", users=f"{user}@pve", roles="Administrator")
        return "Wahoo"
    except Exception as e:
        return str(e)


@app.route("/selfserve", methods=["GET", "POST"])
def selfserve():
    """
    Self-service VM creation page for authenticated users.
    
    GET: Display self-service form
    POST: Authenticate user and create VM based on selection
    
    Legacy endpoint - users can authenticate with their PVE credentials
    and create their own VMs from predefined templates.
    
    Returns:
        GET: Self-service form page
        POST: Success page or error message
    """
    if request.method == "GET":
        if "flash" in request.cookies:
            flash = request.cookies.get("flash")
            pc = render_template("selfserve.html")
            resp = make_response(render_template("page.html", content=pc, flash=flash))
            resp.set_cookie("flash", "", expires=0)
            return resp
        else:
            return render_template("page.html", content=render_template("selfserve.html"))
    else:
        user = request.form.get("username")
        password = request.form.get("password")

        # Basic auth check using PVE user (optional legacy support)
        try:
            ProxmoxAPI(
                PROXMOX_HOST,
                user=f"{user}@pve",
                password=password,
                verify_ssl=PROXMOX_VERIFY_SSL,
            )
            valid = True
        except Exception:
            valid = False
        if valid:
            os = request.form.get("os")
            if os == "win":
                vmid = 2001
            else:
                vmid = 2000

            try:
                prox = get_proxmox()
                nvmid = prox.cluster.nextid.get()
                prox.nodes(PROXMOX_NODE).qemu(vmid).clone.post(
                    newid=nvmid,
                    name=f"{user}-{os}-self",
                    full=0,
                    target=PROXMOX_NODE,
                )
                prox.access.acl.put(path=f"/vms/{nvmid}", users=f"{user}@pve", roles="Administrator")
                return render_template("page.html", content=f"<h2>VM Created: {nvmid}</h2>")
            except Exception as e:
                return render_template("page.html", content=f"<h2>Error: {str(e)}</h2>"), 500
        else:
            resp = make_response(redirect("/selfserve"))
            resp.set_cookie("flash", "Incorrect Password")
            return resp


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
        return render_template("page.html", content=render_template("clone.html"))
    username = request.form.get("username").strip()
    vmid = int(request.form.get("vmid"))
    if not username or not vmid:
        return render_template("page.html", content="<h2>Username and VMID required</h2>"), 400
    
    logger.info(f"Cloning VM {vmid} for user {username}")
    try:
        prox = get_proxmox()
        new_vmid = prox.cluster.nextid.get()
        prox.nodes(PROXMOX_NODE).qemu(vmid).clone.post(
            newid=new_vmid,
            name=f"{username}-range-wk4-{vmid}",
            full=0,
            target=PROXMOX_NODE,
            pool=f"{username}-range"
        )
        
        # Configure network using user-specific vnet
        net0 = f"e1000,bridge={get_vnet_for_user(prox, username)}"
        prox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(net0=net0)
        
        # Grant Administrator role to username@ad on this VM
        prox.access.acl.put(path=f"/vms/{new_vmid}", users=f"{username}@ad", roles="PVEAdmin,Administrator")

        return render_template("page.html", content=f"<h2>Cloned VMID {vmid} to {new_vmid} and granted Administrator to {username}@ad</h2><p>Next, log into Proxmox at <a href='https://192.168.3.236:8006' target='_blank' rel='noopener'>https://192.168.3.236:8006</a></p>")
    except Exception as e:
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
