import sys
import re, os,time
import tomli
from proxmoxer import ProxmoxAPI

def load_secrets():
    with open(os.path.join(os.path.dirname(__file__), "../secrets.toml"), "rb") as f:
        return tomli.load(f)

def main():
    if len(sys.argv) != 2:
        print("Usage: python nuke_by_name.py <pattern>")
        sys.exit(1)
    pattern = sys.argv[1]
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
                print(f"Destroying VM {vmid} ({vm_name}) on node {node_name}")
                if vm['status'] == 'running':
                    print(f"Stopping VM {vmid}...")
                    for i in range(3):
                        proxmox.nodes(node_name).qemu(vmid).status.stop.post(skiplock=1)
                        time.sleep(0.25)
                proxmox.nodes(node_name).qemu(vmid).delete(skiplock=1)

if __name__ == "__main__":
    main()
