import os
import tomli
from proxmoxer import ProxmoxAPI

"""
This script sets up range VMs for each user in the Proxmox environment.
It clones a base gateway VM ~~and two workstation VMs (Xubuntu and Windows)~~
(TODO: make it easy to reconfigure source VMID for workstation(s))
for each user, assigns them to a dedicated pool, and configures their network settings.
"""

def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "../secrets.toml"), "rb") as f:
        return tomli.load(f)

def get_users(proxmox):
    return [u for u in proxmox.access.users.get() if u['userid'].endswith("@ad")]

def get_vnet_for_user(proxmox, username):
    vnets = proxmox.cluster.sdn.vnets.get()
    for vnet in vnets:
        if vnet.get("alias") == username:
            return vnet.get("vnet")
    return None

def ensure_pool(proxmox, pool_name):
    pools = proxmox.pools.get()
    if not any(p['poolid'] == pool_name for p in pools):
        proxmox.pools.post(poolid=pool_name, comment="Range pool for users")
        print(f"Created pool: {pool_name}")

def clone_range_gw(proxmox, base_vmid, new_vmid, name, pool, net_vnet):
    # Clone VM
    proxmox.nodes(PROXMOX_NODE).qemu(base_vmid).clone.post(
        newid=new_vmid,
        name=name,
        pool=pool,
        full=0,
        target=PROXMOX_NODE
    )
    print(f"Cloned VM {base_vmid} to {new_vmid} ({name}) in pool {pool}")

    # Update net0 to use the correct VNet
    net0 = f"virtio,bridge=INFRANET"
    net1 = f"virtio,bridge={net_vnet}"
    proxmox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(net0=net0)
    proxmox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(net1=net1)
    print(f"Updated net0 for VM {new_vmid} to VNet {net_vnet}")

def clone_wks(proxmox, base_vmid, new_vmid, name, pool, net_vnet):
    # Clone VM
    proxmox.nodes(PROXMOX_NODE).qemu(base_vmid).clone.post(
        newid=new_vmid,
        name=name,
        pool=pool,
        full=0,
        target=PROXMOX_NODE
    )
    print(f"Cloned VM {base_vmid} to {new_vmid} ({name}) in pool {pool}")

    # Set net0 to user's VNet
    net0 = f"virtio,bridge={net_vnet}"
    proxmox.nodes(PROXMOX_NODE).qemu(new_vmid).config.post(net0=net0)
    print(f"Set net0 for VM {new_vmid} to VNet {net_vnet}")


def main():
    secrets = load_secrets()
    global PROXMOX_NODE
    PROXMOX_NODE = secrets["proxmox"].get("node", "pve")
    proxmox = ProxmoxAPI(
        secrets["proxmox"]["host"].replace("/api2/json", ""),
        user=secrets["proxmox"]["user"],
        password=secrets["proxmox"]["password"],
        verify_ssl=secrets["proxmox"].get("verify_ssl", True)
    )

    users = get_users(proxmox)
    for idx, user in enumerate(users, start=1):
        if "@ad" not in user['userid']:
            continue
        if "-adm" in user['userid']:
            continue
        username = user['userid'].split("@")[0]
        pool_name = f"{username}-range"
        ensure_pool(proxmox, pool_name)
        # Ensure user has admin and pveadmin permissions on their pool
        proxmox.access.acl.put(
            path=f"/pool/{pool_name}",
            users=user['userid'],
            roles="Administrator,PVEAdmin"
        )
        print(f"Set Admin and PVEAdmin roles for {user['userid']} on pool {pool_name}")
        vnet_name = get_vnet_for_user(proxmox, username)
        if not vnet_name:
            print(f"No VNet found for {username}, skipping.")
            continue

        try:
            # TODO: check if existing VYOS
            new_vmid = proxmox.cluster.nextid.get()
            clone_name = f"{username}-range-vyos"
            clone_range_gw(proxmox, 150, new_vmid, clone_name, pool_name, vnet_name)
            #wks_vmid = proxmox.cluster.nextid.get()
            #win_vmid = proxmox.cluster.nextid.get()
            #clone_wks(proxmox, 151, wks_vmid, f"{username}-range-xubuntu", pool_name, vnet_name)
            #clone_wks(proxmox, 106, win_vmid, f"{username}-range-windows", pool_name, vnet_name)
            proxmox.access.acl.put(
                path=f"/vms/{new_vmid}",
                users=user['userid'],
                roles="Administrator,PVEAdmin"
            )
            print(f"Set Admin and PVEAdmin roles for {user['userid']} on VM {new_vmid}")
            #proxmox.access.acl.put(
            #    path=f"/vms/{wks_vmid}",
            #    users=user['userid'],
            #    roles="Administrator,PVEAdmin"
            #)
            #print(f"Set Admin and PVEAdmin roles for {user['userid']} on VM {wks_vmid}")
        except Exception as e:
            print(f"Error cloning for {username}: {e}")

if __name__ == "__main__":
    main()