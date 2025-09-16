# range
scripts to provision practice environment

## Setup

Install dependencies:

```
pip install -r requirements.txt
```

Create `secrets.toml` in the project root:

```
[proxmox]
host = "192.168.3.236"      # without protocol
user = "root@pam"
password = "your-password"
verify_ssl = false           # or true
node = "pve"

[web]
admin_password = "changeme"          # for /login
default_user_password = "ChangeMe123!"
```

Run the web app:

```
python web.py
```

Pages:
- `/clone`: clone a VM by template VMID and grant `Administrator` to `username@ad` on the cloned VM
- `/selfserve`: legacy self-serve page
