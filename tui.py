import csv, os, sys
from random import randint
from rangemgr import RangeManager, load_secrets


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
    # Load configuration and create manager
    secrets = load_secrets()
    range_manager = RangeManager(secrets)

    running = True

    while running:
        range_manager.vms.get_vms()  # Refresh VM data
        print(
            """1. Create range VMs for user
2. Create range VMs for multiple users
3. Destroy single VM
4. Destroy multiple VMs
5. Destroy ALL range VMs
6. Ensure user VNet
7. Ensure all user VNets
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

            username = input("Username: ")

            # Validate user exists in AD realm
            if not range_manager.users.validate_ad_user(username):
                print(range_manager.users.get_ad_user_error_message(username))
                continue

            # Use the new range manager for VM creation
            for base_vmid in tgt:
                new_vmid = range_manager.proxmox.cluster.nextid.get()
                name = f"{username}-range-{base_vmid}"

                success = range_manager.vms.clone_vm(base_vmid, new_vmid, name)
                if success:
                    # Set permissions for AD user
                    try:
                        range_manager.proxmox.access.acl.put(
                            path=f"/vms/{new_vmid}",
                            users=f"{username}@ad",
                            roles="Administrator",
                        )
                        print(f"Created VM {new_vmid} for {username}@ad")
                    except Exception as e:
                        print(f"Failed to set permissions: {e}")

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
                    username = user[0]

                    # Validate user exists in AD realm
                    if not range_manager.users.validate_ad_user(username):
                        print(
                            f"Skipping {username}: {range_manager.users.get_ad_user_error_message(username)}"
                        )
                        continue

                    print("Making range for: " + str(username) + "@ad")

                    for base_vmid in tgt:
                        new_vmid = range_manager.proxmox.cluster.nextid.get()
                        name = f"{username}-range-{base_vmid}"

                        success = range_manager.vms.clone_vm(base_vmid, new_vmid, name)
                        if success:
                            try:
                                range_manager.proxmox.access.acl.put(
                                    path=f"/vms/{new_vmid}",
                                    users=f"{username}@ad",
                                    roles="Administrator",
                                )
                                print(f"Created VM {new_vmid} for {username}@ad")
                            except Exception as e:
                                print(f"Failed to set permissions: {e}")
                else:
                    print("Skipping " + str(user[0]))

        elif c == "3":
            vmid = int(input("VMID to destroy (NO CONFIRMATION): "))
            range_manager.vms.delete_vm(vmid)

        elif c == "4":
            kaboom = input("Comma-seperated list to remove (NO CONFIRMATION): ")
            for id in kaboom.split(","):
                range_manager.vms.delete_vm(int(id))

        elif c == "5":
            # Destroy all range VMs
            count = range_manager.vms.nuke_by_pattern(r".*range.*")
            print(f"Destroyed {count} range VMs")

        elif c == "6":
            # Sync AD realm
            try:
                range_manager.proxmox.access.domains("ad").sync.post()
                print("Synced AD realm")
            except Exception as e:
                print(f"Warning: AD realm sync failed: {e}")

            username = input("Username: ")

            # Validate user exists in AD realm
            if not range_manager.users.validate_ad_user(username):
                print(range_manager.users.get_ad_user_error_message(username))
                continue

            vnet_name = range_manager.networks.ensure_user_vnet(username)
            if vnet_name:
                print(f"Ensured VNet {vnet_name} for {username}@ad")
            else:
                print(f"Failed to ensure VNet for {username}@ad")

            range_manager.networks.reload_sdn()

        elif c == "7":
            print("Checking VNet for all users")
            # Sync AD realm
            try:
                range_manager.proxmox.access.domains("ad").sync.post()
                print("Synced AD realm")
            except Exception as e:
                print(f"Warning: AD realm sync failed: {e}")

            users = range_manager.users.get_users("ad")
            for user in users:
                userid = user.get("userid")
                if userid and userid.endswith("@ad"):
                    username = userid.split("@")[0]
                    print("Trying to ensure for " + username)
                    range_manager.networks.ensure_user_vnet(username)

            range_manager.networks.reload_sdn()
        elif c.upper() == "Q":
            running = False
