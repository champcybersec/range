
import requests
import json
import time
import getpass
import urllib3
import csv, os, sys
from random import randint

from pveautomate.automate import ProxmoxManager

PROX_URL = os.getenv("PROXMOX_URL", "https://10.10.105.10:8006") + "/api2/json"


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
    proxmox_url = PROX_URL
    proxmox_user = "root@pam"
    proxmox_password = getpass.getpass(f"Authenticate for {proxmox_user}: ")
    node = "pve"

    manager = ProxmoxManager(proxmox_url, proxmox_user, proxmox_password, node)

    running = True

    while running:
        manager.read_vm_data()
        print(
            """1. Create range VMs for user
2. Destroy single VM
3. Destroy multiple VMs
4. Destroy ALL range VMs
5. Create range VMs for multiple users
6. Create new user
7. Bulk Create Users (if not existing already)
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
        elif c == "5":
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
        elif c == "2":
            manager.destroy_vm(int(input("VMID to destroy (NO CONFIRMATION): ")))
        elif c == "3":
            kaboom = input("Comma-seperated list to remove (NO CONFIRMATION): ")
            for id in kaboom.split(","):
                manager.destroy_vm(int(id))
        elif c == "4":
            manager.destroy_range()
        elif c == "6":
            manager.create_user(
                input("Username: "), getpass.getpass("Password: "), "pve"
            )
        elif c == "7":
            fn = input("Filename CSV of users: ")
            newpw = getpass.getpass(
                "Default password for any users we need to create: "
            )
            rows = load_csv(fn)
            if rows is None:
                print("No such file, or other error")
                sys.exit(1)
            else:
                for index, row in enumerate(rows):
                    username = row[0]
                    group = "Proxmox_Users" if row[1] == "user" else "Proxmox_Admins"
                    if not manager.check_if_user(username + "@pve"):  # doesn't exist
                        manager.create_user(username, newpw, "pve")
                        manager.set_user_group(username + "@pve", group)
                        print(f"Created {username}@pve with group {group}")
                    else:
                        print(f"{username} exists. Might have to manually check group?")
        else:
            running = False
