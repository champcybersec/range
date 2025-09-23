import sys
import re, os
import tomli
from proxmoxer import ProxmoxAPI

def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "../secrets.toml"), "rb") as f:
        return tomli.load(f)

def main():
    if len(sys.argv) != 3:
        print("Usage: python set_power_by_name.py <start|stop> <pattern>")
        sys.exit(1)
    action = sys.argv[1].lower()
    if action not in ("start", "stop"):
        print("First argument must be 'start' or 'stop'")
        sys.exit(1)
    pattern = sys.argv[2]
    secrets = load_secrets()
    proxmox = ProxmoxAPI(
        secrets['proxmox']['host'],
        user=secrets['proxmox']['user'],
        password=secrets['proxmox']['password'],
        verify_ssl=False
    )
    regex = re.compile(pattern)
    for node in proxmox.nodes.get():
        node_name = node['node']
        for vm in proxmox.nodes(node_name).qemu.get():
            vm_name = vm.get('name', '')
            if regex.search(vm_name):
                vmid = vm['vmid']
                status = proxmox.nodes(node_name).qemu(vmid).status.current.get()['status']
                if action == "start":
                    if status != 'running':
                        print(f"Starting VM {vmid} ({vm_name}) on node {node_name}")
                        proxmox.nodes(node_name).qemu(vmid).status.start.post()
                    else:
                        print(f"VM {vmid} ({vm_name}) is already running.")
                elif action == "stop":
                    if status == 'running':
                        print(f"Stopping VM {vmid} ({vm_name}) on node {node_name}")
                        proxmox.nodes(node_name).qemu(vmid).status.stop.post()
                    else:
                        print(f"VM {vmid} ({vm_name}) is already stopped.")

if __name__ == "__main__":
    main()