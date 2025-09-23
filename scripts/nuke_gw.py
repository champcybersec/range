import os
import tomli
from proxmoxer import ProxmoxAPI

def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "../secrets.toml"), "rb") as f:
        return tomli.load(f)

def main():
    secrets = load_secrets()
    node = secrets["proxmox"].get("node", "pve")
    proxmox = ProxmoxAPI(
        secrets["proxmox"]["host"].replace("/api2/json", ""),
        user=secrets["proxmox"]["user"],
        password=secrets["proxmox"]["password"],
        verify_ssl=secrets["proxmox"].get("verify_ssl", True)
    )

    vms = proxmox.nodes(node).qemu.get()
    for vm in vms:
        name = vm.get("name", "")
        if name.endswith("-range-gw"):
            vmid = vm["vmid"]
            try:
                proxmox.nodes(node).qemu(vmid).delete()
                print(f"Deleted VM {vmid} ({name})")
            except Exception as e:
                print(f"Failed to delete VM {vmid} ({name}): {e}")

if __name__ == "__main__":
    main()