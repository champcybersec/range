import os
import tomli
from proxmoxer import ProxmoxAPI

def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "../secrets.toml"), "rb") as f:
        return tomli.load(f)

def load_vnets(vnet_file):
    with open(vnet_file, "r") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    secrets = load_secrets()
    proxmox = ProxmoxAPI(
        secrets["proxmox"]["host"].replace("/api2/json", ""),
        user=secrets["proxmox"]["user"],
        password=secrets["proxmox"]["password"],
        verify_ssl=secrets["proxmox"].get("verify_ssl", True)
    )

    vnets = load_vnets(os.path.join(os.path.dirname(__file__), "../.vnet"))
    for vnet_name in vnets:
        try:
            proxmox.cluster.sdn.vnets(vnet_name).delete()
            print(f"Deleted VNet: {vnet_name}")
        except Exception as e:
            print(f"Failed to delete VNet {vnet_name}: {e}")

    os.remove(os.path.join(os.path.dirname(__file__), "../.vnet"))

if __name__ == "__main__":
    main()