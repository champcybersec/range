"""
Proxmox Range Management Library

This module provides a unified interface for managing Proxmox VMs, users, and networks
in a competitive cyber training environment. It consolidates functionality from various
scripts that were previously scattered across the scripts/ directory.

Classes:
    RangeManager: Main class for Proxmox operations
    VMManager: VM lifecycle operations (create, clone, delete, power control)
    UserManager: User and authentication management  
    NetworkManager: VNet and SDN configuration management

Functions:
    load_secrets(): Load configuration from secrets.toml
    get_proxmox_client(): Create authenticated ProxmoxAPI client
"""

import os
import re
import time
import tomli
import urllib.parse
import requests
from typing import Dict, List, Any, Optional
from proxmoxer import ProxmoxAPI
import logging

logger = logging.getLogger(__name__)


def load_secrets(secrets_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration secrets from secrets.toml file.
    
    Args:
        secrets_path: Optional path to secrets file. If None, uses default location.
        
    Returns:
        Dict containing configuration sections for proxmox, web, etc.
        
    Raises:
        FileNotFoundError: If secrets.toml file is not found
        tomli.TOMLDecodeError: If the TOML file is malformed
    """
    if secrets_path is None:
        secrets_path = os.path.join(os.path.dirname(__file__), "secrets.toml")
    
    logger.debug(f"Loading secrets from {secrets_path}")
    with open(secrets_path, "rb") as f:
        return tomli.load(f)


def get_proxmox_client(secrets: Optional[Dict[str, Any]] = None) -> ProxmoxAPI:
    """
    Create and return an authenticated ProxmoxAPI client.
    
    Args:
        secrets: Optional secrets dict. If None, loads from default location.
        
    Returns:
        Configured ProxmoxAPI client instance
        
    Raises:
        Exception: If connection to Proxmox fails
    """
    if secrets is None:
        secrets = load_secrets()
    
    proxmox_config = secrets["proxmox"]
    host = proxmox_config["host"]
    
    # Clean up host URL for proxmoxer
    if host.endswith("/api2/json"):
        host = host.replace("/api2/json", "")
    
    logger.debug(f"Connecting to Proxmox at {host} as {proxmox_config['user']}")
    
    try:
        return ProxmoxAPI(
            host,
            user=proxmox_config["user"],
            password=proxmox_config["password"],
            verify_ssl=proxmox_config.get("verify_ssl", True)
        )
    except Exception as e:
        logger.error(f"Failed to connect to Proxmox: {e}")
        raise


class VMManager:
    """Handles VM lifecycle operations like create, clone, delete, and power control."""
    
    def __init__(self, proxmox: ProxmoxAPI, node: str):
        self.proxmox = proxmox
        self.node = node
    
    def get_vms(self) -> List[Dict[str, Any]]:
        """Get list of all VMs on the node."""
        return self.proxmox.nodes(self.node).qemu.get()
    
    def find_vms_by_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """Find VMs matching a regex pattern in their name."""
        regex = re.compile(pattern)
        vms = self.get_vms()
        return [vm for vm in vms if regex.search(vm.get('name', ''))]
    
    def find_vms_by_suffix(self, suffix: str) -> List[Dict[str, Any]]:
        """Find VMs with names ending in a specific suffix."""
        vms = self.get_vms()
        return [vm for vm in vms if vm.get('name', '').endswith(suffix)]
    
    def delete_vm(self, vmid: int, force: bool = False) -> bool:
        """
        Delete a VM by VMID.
        
        Args:
            vmid: VM ID to delete
            force: If True, uses skiplock=1
            
        Returns:
            True if successful, False otherwise
        """
        try:
            kwargs = {"skiplock": 1} if force else {}
            self.proxmox.nodes(self.node).qemu(vmid).delete(**kwargs)
            logger.info(f"Deleted VM {vmid}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete VM {vmid}: {e}")
            return False
    
    def stop_vm(self, vmid: int, force: bool = False) -> bool:
        """
        Stop a VM by VMID.
        
        Args:
            vmid: VM ID to stop
            force: If True, uses skiplock=1
            
        Returns:
            True if successful, False otherwise
        """
        try:
            kwargs = {"skiplock": 1} if force else {}
            self.proxmox.nodes(self.node).qemu(vmid).status.stop.post(**kwargs)
            logger.info(f"Stopped VM {vmid}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop VM {vmid}: {e}")
            return False
    
    def start_vm(self, vmid: int) -> bool:
        """
        Start a VM by VMID.
        
        Args:
            vmid: VM ID to start
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.proxmox.nodes(self.node).qemu(vmid).status.start.post()
            logger.info(f"Started VM {vmid}")
            return True
        except Exception as e:
            logger.error(f"Failed to start VM {vmid}: {e}")
            return False
    
    def get_vm_status(self, vmid: int) -> Optional[str]:
        """Get the current status of a VM."""
        try:
            status = self.proxmox.nodes(self.node).qemu(vmid).status.current.get()
            return status.get('status')
        except Exception as e:
            logger.error(f"Failed to get status for VM {vmid}: {e}")
            return None
    
    def set_power_by_pattern(self, pattern: str, action: str) -> int:
        """
        Start or stop VMs matching a pattern.
        
        Args:
            pattern: Regex pattern to match VM names
            action: 'start' or 'stop'
            
        Returns:
            Number of VMs affected
        """
        if action not in ('start', 'stop'):
            raise ValueError("Action must be 'start' or 'stop'")
        
        affected_count = 0
        # Search across all nodes, not just the configured one
        for node in self.proxmox.nodes.get():
            node_name = node['node']
            vms = self.proxmox.nodes(node_name).qemu.get()
            regex = re.compile(pattern)
            
            for vm in vms:
                vm_name = vm.get('name', '')
                if regex.search(vm_name):
                    vmid = vm['vmid']
                    current_status = vm.get('status', 'unknown')
                    
                    if action == 'start' and current_status != 'running':
                        if self.proxmox.nodes(node_name).qemu(vmid).status.start.post():
                            logger.info(f"Started VM {vmid} ({vm_name}) on node {node_name}")
                            affected_count += 1
                    elif action == 'stop' and current_status == 'running':
                        if self.proxmox.nodes(node_name).qemu(vmid).status.stop.post():
                            logger.info(f"Stopped VM {vmid} ({vm_name}) on node {node_name}")
                            affected_count += 1
                    else:
                        logger.debug(f"VM {vmid} ({vm_name}) already in desired state")
        
        return affected_count
    
    def nuke_by_pattern(self, pattern: str, stop_first: bool = True) -> int:
        """
        Delete all VMs matching a pattern.
        
        Args:
            pattern: Regex pattern to match VM names
            stop_first: If True, stop running VMs before deletion
            
        Returns:
            Number of VMs deleted
        """
        deleted_count = 0
        # Search across all nodes
        for node in self.proxmox.nodes.get():
            node_name = node['node']
            vms = self.proxmox.nodes(node_name).qemu.get()
            regex = re.compile(pattern)
            
            for vm in vms:
                vm_name = vm.get('name', '')
                if regex.search(vm_name):
                    vmid = vm['vmid']
                    logger.info(f"Destroying VM {vmid} ({vm_name}) on node {node_name}")
                    
                    if stop_first and vm.get('status') == 'running':
                        logger.info(f"Stopping VM {vmid}...")
                        # Try multiple times to ensure it stops
                        for i in range(3):
                            try:
                                self.proxmox.nodes(node_name).qemu(vmid).status.stop.post(skiplock=1)
                                time.sleep(0.25)
                            except Exception as e:
                                logger.warning(f"Stop attempt {i+1} failed for VM {vmid}: {e}")
                    
                    try:
                        self.proxmox.nodes(node_name).qemu(vmid).delete(skiplock=1)
                        deleted_count += 1
                        logger.info(f"Deleted VM {vmid} ({vm_name})")
                    except Exception as e:
                        logger.error(f"Failed to delete VM {vmid}: {e}")
        
        return deleted_count
    
    def nuke_gateway_vms(self) -> int:
        """Delete all VMs with names ending in '-range-gw'."""
        return self.nuke_by_pattern(r'.*-range-gw$')
    
    def clone_vm(self, base_vmid: int, new_vmid: int, name: str, 
                 pool: Optional[str] = None, full_clone: bool = False) -> bool:
        """
        Clone a VM.
        
        Args:
            base_vmid: Source VM ID to clone from
            new_vmid: New VM ID for the clone
            name: Name for the new VM
            pool: Optional pool to assign the VM to
            full_clone: Whether to make a full clone (default: linked clone)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            clone_params = {
                "newid": new_vmid,
                "name": name,
                "full": 1 if full_clone else 0,
                "target": self.node
            }
            
            if pool:
                clone_params["pool"] = pool
            
            self.proxmox.nodes(self.node).qemu(base_vmid).clone.post(**clone_params)
            logger.info(f"Cloned VM {base_vmid} to {new_vmid} ({name})")
            return True
        except Exception as e:
            logger.error(f"Failed to clone VM {base_vmid} to {new_vmid}: {e}")
            return False


class UserManager:
    """Handles user management operations."""
    
    def __init__(self, proxmox: ProxmoxAPI):
        self.proxmox = proxmox
    
    def get_users(self, realm_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get list of users, optionally filtered by realm.
        
        Args:
            realm_filter: Optional realm to filter by (e.g., 'ad', 'pve')
            
        Returns:
            List of user dictionaries
        """
        users = self.proxmox.access.users.get()
        if realm_filter:
            return [u for u in users if u['userid'].endswith(f"@{realm_filter}")]
        return users
    
    def user_exists(self, userid: str) -> bool:
        """Check if a user exists."""
        users = self.get_users()
        return any(user.get('userid') == userid for user in users)
    
    def create_user(self, username: str, password: str, realm: str = "pve") -> bool:
        """
        Create a new user.
        
        Args:
            username: Username (without realm)
            password: User password
            realm: Authentication realm
            
        Returns:
            True if successful, False otherwise
        """
        try:
            userid = f"{username}@{realm}"
            self.proxmox.access.users.post(
                userid=userid,
                password=password
            )
            logger.info(f"Created user {userid}")
            return True
        except Exception as e:
            logger.error(f"Error creating user {username}@{realm}: {e}")
            return False
    
    def delete_user(self, userid: str) -> bool:
        """
        Delete a user.
        
        Args:
            userid: Full user ID including realm (e.g., 'user@pve')
            
        Returns:
            True if deleted, False if not found or failed
        """
        try:
            # URL encode the userid for the API call
            encoded_userid = urllib.parse.quote(userid, safe='')
            response = self.proxmox.access.users(encoded_userid).delete()
            logger.info(f"Deleted user {userid}")
            return True
        except Exception as e:
            if "does not exist" in str(e).lower() or "404" in str(e):
                logger.warning(f"User {userid} not found")
                return False
            logger.error(f"Error deleting user {userid}: {e}")
            return False
    
    def purge_pve_users(self, dry_run: bool = False) -> int:
        """
        Delete all users in the 'pve' realm.
        
        Args:
            dry_run: If True, only log what would be deleted
            
        Returns:
            Number of users processed
        """
        pve_users = self.get_users("pve")
        processed_count = 0
        
        for user in pve_users:
            userid = user.get('userid')
            if not userid:
                continue
                
            if dry_run:
                logger.info(f"[DRYRUN] Would delete {userid}")
            else:
                if self.delete_user(userid):
                    logger.info(f"[OK] Deleted {userid}")
                else:
                    logger.warning(f"[SKIP] Could not delete {userid}")
            processed_count += 1
        
        return processed_count


class NetworkManager:
    """Handles network and VNet operations."""
    
    def __init__(self, proxmox: ProxmoxAPI):
        self.proxmox = proxmox
    
    def get_vnets(self) -> List[Dict[str, Any]]:
        """Get list of all VNets."""
        try:
            return self.proxmox.cluster.sdn.vnets.get()
        except Exception as e:
            logger.error(f"Failed to get VNets: {e}")
            return []
    
    def get_vnet_for_user(self, username: str) -> Optional[str]:
        """
        Get the VNet assigned to a specific user.
        
        Args:
            username: Username to look up
            
        Returns:
            VNet name if found, None otherwise
        """
        try:
            vnets = self.get_vnets()
            for vnet in vnets:
                if vnet.get("alias") == username:
                    return vnet.get("vnet")
            logger.debug(f"No VNet found for user {username}")
            return None
        except Exception as e:
            logger.error(f"Failed to get VNet for user {username}: {e}")
            return None
    
    def create_vnet(self, vnet_name: str, zone: str, alias: Optional[str] = None) -> bool:
        """
        Create a new VNet.
        
        Args:
            vnet_name: Name of the VNet
            zone: SDN zone to create the VNet in
            alias: Optional alias for the VNet
            
        Returns:
            True if successful, False otherwise
        """
        try:
            params = {
                "vnet": vnet_name,
                "zone": zone
            }
            if alias:
                params["alias"] = alias
            
            self.proxmox.cluster.sdn.vnets.post(**params)
            logger.info(f"Created VNet '{vnet_name}' in zone '{zone}'")
            return True
        except Exception as e:
            logger.error(f"Failed to create VNet {vnet_name}: {e}")
            return False
    
    def delete_vnet(self, vnet_name: str) -> bool:
        """
        Delete a VNet.
        
        Args:
            vnet_name: Name of the VNet to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.proxmox.cluster.sdn.vnets(vnet_name).delete()
            logger.info(f"Deleted VNet: {vnet_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete VNet {vnet_name}: {e}")
            return False
    
    def ensure_user_vnet(self, username: str, zone: str = "CMPCCDC") -> Optional[str]:
        """
        Ensure a VNet exists for a user.
        
        Args:
            username: Username to create VNet for
            zone: SDN zone to create VNet in
            
        Returns:
            VNet name if successful, None otherwise
        """
        try:
            # Generate VNet name from username
            if '.' in username:
                parts = username.split('.')
            else:
                parts = ['N', username[0]]
            
            vnet_name = f"RN{parts[0][0]}{parts[1][0]}"
            
            # Check if VNet already exists
            vnets = self.get_vnets()
            vnet_exists = any(v.get("vnet") == vnet_name for v in vnets)
            
            if not vnet_exists:
                if self.create_vnet(vnet_name, zone, username):
                    return vnet_name
                else:
                    return None
            else:
                logger.info(f"VNet '{vnet_name}' already exists for user {username}")
                return vnet_name
                
        except Exception as e:
            logger.error(f"Error ensuring VNet for {username}: {e}")
            return None
    
    def reload_sdn(self) -> bool:
        """Reload SDN configuration."""
        try:
            self.proxmox.cluster.sdn.reload.post()
            logger.info("Reloaded SDN configuration")
            return True
        except Exception as e:
            logger.error(f"Failed to reload SDN: {e}")
            return False


class PoolManager:
    """Handles pool operations."""
    
    def __init__(self, proxmox: ProxmoxAPI):
        self.proxmox = proxmox
    
    def get_pools(self) -> List[Dict[str, Any]]:
        """Get list of all pools."""
        return self.proxmox.pools.get()
    
    def pool_exists(self, pool_name: str) -> bool:
        """Check if a pool exists."""
        pools = self.get_pools()
        return any(p['poolid'] == pool_name for p in pools)
    
    def create_pool(self, pool_name: str, comment: Optional[str] = None) -> bool:
        """
        Create a new pool.
        
        Args:
            pool_name: Name of the pool to create
            comment: Optional comment for the pool
            
        Returns:
            True if successful, False otherwise
        """
        try:
            params = {"poolid": pool_name}
            if comment:
                params["comment"] = comment
            
            self.proxmox.pools.post(**params)
            logger.info(f"Created pool: {pool_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create pool {pool_name}: {e}")
            return False
    
    def ensure_pool(self, pool_name: str, comment: Optional[str] = None) -> bool:
        """
        Ensure a pool exists, creating it if necessary.
        
        Args:
            pool_name: Name of the pool
            comment: Optional comment for new pools
            
        Returns:
            True if pool exists or was created successfully
        """
        if self.pool_exists(pool_name):
            logger.debug(f"Pool {pool_name} already exists")
            return True
        
        return self.create_pool(pool_name, comment or "Range pool for users")


class RangeManager:
    """
    Main class that provides high-level operations for range management.
    
    This class combines VM, user, network, and pool management to provide
    the main functionality needed for competitive cyber training scenarios.
    """
    
    def __init__(self, secrets: Optional[Dict[str, Any]] = None):
        """
        Initialize the RangeManager.
        
        Args:
            secrets: Optional secrets dict. If None, loads from default location.
        """
        if secrets is None:
            secrets = load_secrets()
        
        self.secrets = secrets
        self.proxmox = get_proxmox_client(secrets)
        self.node = secrets["proxmox"].get("node", "pve")
        
        # Initialize component managers
        self.vms = VMManager(self.proxmox, self.node)
        self.users = UserManager(self.proxmox)
        self.networks = NetworkManager(self.proxmox)
        self.pools = PoolManager(self.proxmox)
    
    def setup_user_range(self, username: str, base_vmid: int = 150, 
                        pool_suffix: str = "-range") -> bool:
        """
        Set up a complete range environment for a user.
        
        This includes:
        - Creating a dedicated pool
        - Setting up a VNet
        - Cloning a gateway VM
        - Setting appropriate permissions
        
        Args:
            username: Username (without realm)
            base_vmid: Base VM ID to clone from
            pool_suffix: Suffix for the pool name
            
        Returns:
            True if successful, False otherwise
        """
        try:
            pool_name = f"{username}{pool_suffix}"
            
            # Ensure pool exists
            if not self.pools.ensure_pool(pool_name):
                return False
            
            # Ensure VNet exists
            vnet_name = self.networks.ensure_user_vnet(username)
            if not vnet_name:
                logger.error(f"Failed to ensure VNet for {username}")
                return False
            
            # Get next available VM ID
            new_vmid = self.proxmox.cluster.nextid.get()
            clone_name = f"{username}-range-vyos"
            
            # Clone the gateway VM
            if not self.vms.clone_vm(base_vmid, new_vmid, clone_name, pool_name):
                return False
            
            # Configure networking for the cloned VM
            self._configure_vm_networking(new_vmid, vnet_name)
            
            # Set user permissions
            self._set_user_permissions(f"{username}@ad", pool_name, new_vmid)
            
            logger.info(f"Successfully set up range for {username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup range for {username}: {e}")
            return False
    
    def _configure_vm_networking(self, vmid: int, vnet_name: str):
        """Configure networking for a cloned VM."""
        try:
            # Set net0 to INFRANET and net1 to user's VNet
            net0 = "virtio,bridge=INFRANET"
            net1 = f"virtio,bridge={vnet_name}"
            
            self.proxmox.nodes(self.node).qemu(vmid).config.post(net0=net0)
            self.proxmox.nodes(self.node).qemu(vmid).config.post(net1=net1)
            
            logger.info(f"Configured networking for VM {vmid} with VNet {vnet_name}")
        except Exception as e:
            logger.error(f"Failed to configure networking for VM {vmid}: {e}")
    
    def _set_user_permissions(self, userid: str, pool_name: str, vmid: int):
        """Set user permissions on pool and VM."""
        try:
            # Set permissions on pool
            self.proxmox.access.acl.put(
                path=f"/pool/{pool_name}",
                users=userid,
                roles="Administrator,PVEAdmin"
            )
            
            # Set permissions on VM
            self.proxmox.access.acl.put(
                path=f"/vms/{vmid}",
                users=userid,
                roles="Administrator,PVEAdmin"
            )
            
            logger.info(f"Set permissions for {userid} on pool {pool_name} and VM {vmid}")
        except Exception as e:
            logger.error(f"Failed to set permissions for {userid}: {e}")