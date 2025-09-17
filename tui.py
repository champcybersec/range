import requests
import json
import time
import urllib3
import csv, os, sys
from random import randint
import tomli

from proxmoxer import ProxmoxAPI

def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "secrets.toml"), "rb") as f:
        return tomli.load(f)


secrets = load_secrets()
PROXMOX_HOST = secrets["proxmox"]["host"]
PROXMOX_USER = secrets["proxmox"]["user"]
PROXMOX_PASSWORD = secrets["proxmox"]["password"]
PROXMOX_VERIFY_SSL = secrets["proxmox"].get("verify_ssl", True)
PROXMOX_NODE = secrets["proxmox"].get("node", "pve")
DEFAULT_USER_PASSWORD = secrets.get("web", {}).get("default_user_password", "ChangeMe123!")

class ProxmoxManager:
    def __init__(self, proxmox_url, proxmox_user, proxmox_password, node):
        # Remove /api2/json from URL if present for proxmoxer
        if proxmox_url.endswith("/api2/json"):
            proxmox_url = proxmox_url.replace("/api2/json", "")
        
        self.proxmox = ProxmoxAPI(
            proxmox_url,
            user=proxmox_user,
            password=proxmox_password,
            verify_ssl=PROXMOX_VERIFY_SSL
        )
        self.node = node
        self.vm_data = {}

    def read_vm_data(self):
        """Read VM data from Proxmox"""
        try:
            vms = self.proxmox.nodes(self.node).qemu.get()
            self.vm_data = {vm['vmid']: vm for vm in vms}
            return self.vm_data
        except Exception as e:
            print(f"Error reading VM data: {e}")
            return {}

    def create_range(self, vmids, username):
        """Create range VMs for a user by cloning existing VMs"""
        try:
            for base_vmid in vmids:
                # Get next available VMID
                new_vmid = self.proxmox.cluster.nextid.get()
                name = f"{username}-range-{base_vmid}"
                
                # Clone the VM
                self.proxmox.nodes(self.node).qemu(base_vmid).clone.post(
                    newid=new_vmid,
                    name=name,
                    full=0,
                    target=self.node
                )
                
                # Assign Administrator role to user
                self.proxmox.access.acl.put(
                    path=f"/vms/{new_vmid}",
                    users=f"{username}@pve",
                    roles="Administrator"
                )
                print(f"Created VM {new_vmid} for {username}")
        except Exception as e:
            print(f"Error creating range: {e}")

    def destroy_vm(self, vmid):
        """Destroy a single VM"""
        try:
            self.proxmox.nodes(self.node).qemu(vmid).delete()
            print(f"Destroyed VM {vmid}")
        except Exception as e:
            print(f"Error destroying VM {vmid}: {e}")

    def destroy_range(self):
        """Destroy all range VMs"""
        try:
            vms = self.proxmox.nodes(self.node).qemu.get()
            range_vms = [vm for vm in vms if 'range' in vm.get('name', '').lower()]
            for vm in range_vms:
                self.proxmox.nodes(self.node).qemu(vm['vmid']).delete()
                print(f"Destroyed range VM {vm['vmid']} ({vm.get('name', '')})")
        except Exception as e:
            print(f"Error destroying range VMs: {e}")

    def create_user(self, username, password, realm="pve"):
        """Create a new user"""
        try:
            userid = f"{username}@{realm}"
            self.proxmox.access.users.post(
                userid=userid,
                password=password
            )
            print(f"Created user {userid}")
        except Exception as e:
            print(f"Error creating user {username}: {e}")

    def check_if_user(self, userid):
        """Check if a user exists"""
        try:
            users = self.proxmox.access.users.get()
            return any(user.get('userid') == userid for user in users)
        except Exception as e:
            print(f"Error checking user {userid}: {e}")
            return False

    def get_users(self):
        """Get all users"""
        try:
            users = self.proxmox.access.users.get()
            return users
        except Exception as e:
            print(f"Error getting users: {e}")
            return []

    def set_user_group(self, userid, group):
        """Set user group (Note: This is a simplified implementation)"""
        try:
            # Proxmox doesn't have direct group assignment via API
            # This would typically be handled through ACL or other means
            print(f"Note: Group assignment for {userid} to {group} would need manual configuration")
        except Exception as e:
            print(f"Error setting user group: {e}")

    def sync_realm(self, realm="ad"):
        try:
            self.proxmox.access.domains(realm).sync.post()
            print(f"Synced '{realm}' realm")
        except Exception as sync_err:
            print(f"Warning: realm sync for '{realm}' failed or not available: {sync_err}")

    def net_reload(self):
        # Apply SDN config changes
            try:
                self.proxmox.cluster.sdn.reload.post()
                print("Reloaded SDN configuration")
            except Exception as reload_err:
                print(f"Warning: SDN reload failed: {reload_err}")


    def ensure_user_vnet(self, username, realm="ad"):
        """Ensure a per-user VNet exists under the CMPCCDC zone.

        Steps:
        - Force a sync of the specified auth realm (default: ad)
        - Ensure a VNet named after the user exists in the CMPCCDC zone.
        - Reload SDN to apply changes
        """
        try:
 
            zone_name = "CMPCCDC"
            if '.' in username:
                tb = username.split('.')
            else:
                tb = ['N', username[0]]
            vnet_name = f"RN{tb[0]}{tb[1]}"
            with open(".vnet","a+") as f:
                f.write(vnet_name+"\n")

            # Check existing SDN VNets
            vnets = self.proxmox.cluster.sdn.vnets.get()
            vnet_exists = any(v.get("vnet") == vnet_name for v in vnets)

            if not vnet_exists:
                # Create a VNet for this user in the CMPCCDC zone
                self.proxmox.cluster.sdn.vnets.post(
                    vnet=vnet_name,
                    zone=zone_name,
                    alias=username
                )
                print(f"Created VNet '{vnet_name}' in zone '{zone_name}'")
            else:
                print(f"VNet '{vnet_name}' already exists in zone '{zone_name}'")

        except Exception as e:
            print(f"Error ensuring VNet for {username}: {e}")

def load_csv(file_name):
    try:
        with open(file_name) as file:
            reader = csv.reader(file)
            rows = [row for row in reader]
            return rows
    except:
        print("Something funky")
        return None


if __name__ == "__main__":
    manager = ProxmoxManager(PROXMOX_HOST, PROXMOX_USER, PROXMOX_PASSWORD, PROXMOX_NODE)

    running = True

    while running:
        manager.read_vm_data()
        print(
            """1. Create range VMs for user
2. Create range VMs for multiple users
3. Destroy single VM
4. Destroy multiple VMs
5. Destroy ALL range VMs
6. Create new user
7. Bulk Create Users (if not existing already)
8. Ensure user VNet
9. Ensure all user VNets
Q. Quit"""
        )
        c = input("> ")
        if c == "1":
            vmids = input("Comma seperated list of VMIDs (or just one): ")
            tgt = []
            if not "," in vmids:
                tgt.append(int(vmids))
            else:
                stuff = vmids.split(",")
                for vid in stuff:
                    tgt.append(int(vid))
            manager.create_range(tgt, input("Username: "))
        elif c == "2":
            vmids = input("Comma seperated list of VMIDs (or just one): ")
            tgt = []
            if not "," in vmids:
                tgt.append(int(vmids))
            else:
                stuff = vmids.split(",")
                for vid in stuff:
                    tgt.append(int(vid))

            users = load_csv("range_users.csv")

            for user in users:
                if user[1] != "admin":
                    print("Making range for: " + str(user[0]) + "@pve")
                    manager.create_range(tgt, user[0]+"@pve")
                else:
                    print("Skipping " + str(user[0]))
        elif c == "3":
            manager.destroy_vm(int(input("VMID to destroy (NO CONFIRMATION): ")))
        elif c == "4":
            kaboom = input("Comma-seperated list to remove (NO CONFIRMATION): ")
            for id in kaboom.split(","):
                manager.destroy_vm(int(id))
        elif c == "5":
            manager.destroy_range()
        elif c == "6":
            manager.create_user(
                input("Username: "), input("Password: "), "pve"
            )
        elif c == "7": # TODO: this is all @pve still
            fn = input("Filename CSV of users: ")
            rows = load_csv(fn)
            if rows is None:
                print("No such file, or other error")
                sys.exit(1)
            else:
                for index, row in enumerate(rows):
                    username = row[0]
                    group = "Proxmox_Users" if row[1] == "user" else "Proxmox_Admins"
                    if not manager.check_if_user(username + "@pve"):  # doesn't exist
                        manager.create_user(username, DEFAULT_USER_PASSWORD, "pve")
                        #manager.set_user_group(username + "@pve", group)
                        print(f"Created {username}@pve")
                    else:
                        print(f"{username} exists. Might have to manually check group?")
        elif c == "8":
            manager.sync_realm()
            manager.ensure_user_vnet(input("Username: "))
            manager.net_reload()
        elif c == "9":
            print("Checking VNet for all users")
            manager.sync_realm()
            users = manager.get_users()
            for user in users:
                if user['userid'].endswith("@ad"):
                    username = user['userid'].split('@')[0]
                    print("Trying to ensure for " + username)
                    manager.ensure_user_vnet(username)
            manager.net_reload()
        else:
            running = False