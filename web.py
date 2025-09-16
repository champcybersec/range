from flask import Flask, render_template, request, make_response, redirect
from proxmoxer import ProxmoxAPI
import os
import random
import tomli

app = Flask(__name__)


def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "secrets.toml"), "rb") as f:
        return tomli.load(f)


secrets = load_secrets()
PROXMOX_HOST = secrets["proxmox"]["host"]  # e.g. 192.168.3.236
PROXMOX_USER = secrets["proxmox"]["user"]  # e.g. root@pam
PROXMOX_PASSWORD = secrets["proxmox"]["password"]
PROXMOX_VERIFY_SSL = secrets["proxmox"].get("verify_ssl", True)
PROXMOX_NODE = secrets["proxmox"].get("node", "pve")

SUPER_SECRET = secrets.get("web", {}).get("admin_password", "changeme")
AUTHK = "yup"

DEFAULT_USER_PASSWORD = secrets.get("web", {}).get("default_user_password", "ChangeMe123!")


def get_proxmox() -> ProxmoxAPI:
    return ProxmoxAPI(
        PROXMOX_HOST,
        user=PROXMOX_USER,
        password=PROXMOX_PASSWORD,
        verify_ssl=PROXMOX_VERIFY_SSL,
    )


@app.route("/")
def home():
    return render_template(
        "page.html", content="<h2>Home</h2><p><a href='/clone'>Clone VM</a><br/><br/><a href='/login'>Admin Login</a>"
    )


@app.route("/login", methods=["GET", "POST"])
def login():
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
    resp = make_response(redirect(request.args.get("next", "/")))
    resp.set_cookie("sk-lol", "", expires=0)
    return resp


@app.route("/admin")
def adm():
    if request.cookies.get("sk-lol") == AUTHK:
        return render_template("admin.html", prox_login=PROXMOX_USER, passw=DEFAULT_USER_PASSWORD)
    else:
        return redirect("/login?next=/admin")


@app.route("/ensure", methods=["POST"])
def ensure():
    if request.cookies.get("sk-lol") != AUTHK:
        return redirect("/login")
    else:
        data = request.get_json()

        usernames = data["usernames"].split(",")

        for username in usernames:
            uid = username + "@pve"
            # Create a PVE local user if missing (migration helper)
            prox = get_proxmox()
            users = prox.access.users.get()
            if not any(u.get("userid") == uid for u in users):
                prox.access.users.post(userid=uid, password=DEFAULT_USER_PASSWORD)

        return "Wahoo"


@app.route("/range", methods=["POST"])
def mrange():
    if request.cookies.get("sk-lol") != AUTHK:
        return redirect("/login")

    vmids = [int(vm_id) for vm_id in request.get_json()["vmids"].split(",")]
    users = request.get_json()["usernames"].split(",")

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
    if request.method == "GET":
        return render_template("page.html", content=render_template("clone.html"))
    username = request.form.get("username").strip()
    vmid = int(request.form.get("vmid"))
    if not username or not vmid:
        return render_template("page.html", content="<h2>Username and VMID required</h2>"), 400
    try:
        prox = get_proxmox()
        new_vmid = prox.cluster.nextid.get()
        prox.nodes(PROXMOX_NODE).qemu(vmid).clone.post(
            newid=new_vmid,
            name=f"{username}-clone-{vmid}",
            full=0,
            target=PROXMOX_NODE,
        )
        # Grant Administrator role to username@ad on this VM
        prox.access.acl.put(path=f"/vms/{new_vmid}", users=f"{username}@ad", roles="Administrator")
        return render_template("page.html", content=f"<h2>Cloned VMID {vmid} to {new_vmid} and granted Administrator to {username}@ad</h2>")
    except Exception as e:
        return render_template("page.html", content=f"<h2>Error: {str(e)}</h2>"), 500

@app.errorhandler(404)
def page_not_found(e):
    return (
        render_template(
            "page.html",
            content="<h2>Page not found. Please check spelling and try again</h2>",
        ),
        404,
    )


@app.errorhandler(500)
def uhoh_yikes(e):
    return (
        render_template(
            "page.html",
            content=f"<h2>Internal Server Error</h2><br/><pre><code>{str(e)}</code></pre>",
        ),
        500,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7878)
