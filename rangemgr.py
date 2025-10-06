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


def load_vmids(vmids_path: Optional[str] = None) -> Dict[str, str]:
    """
    Load VM template configuration from vmids.toml file.

    Args:
        vmids_path: Optional path to vmids file. If None, uses default location.

    Returns:
        Dict mapping VMID strings to human-readable names

    Raises:
        FileNotFoundError: If vmids.toml file is not found
        tomli.TOMLDecodeError: If the TOML file is malformed
    """
    if vmids_path is None:
        vmids_path = os.path.join(os.path.dirname(__file__), "vmids.toml")

    logger.debug(f"Loading VM templates from {vmids_path}")
    with open(vmids_path, "rb") as f:
        config = tomli.load(f)
        return config.get("templates", {})


def load_infra_config(infra_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load infrastructure configuration from infra.toml file.

    Args:
        infra_path: Optional path to infra file. If None, uses default location.

    Returns:
        Dict containing infrastructure configuration sections

    Raises:
        FileNotFoundError: If infra.toml file is not found
        tomli.TOMLDecodeError: If the TOML file is malformed
    """
    if infra_path is None:
        infra_path = os.path.join(os.path.dirname(__file__), "infra.toml")

    logger.debug(f"Loading infrastructure config from {infra_path}")
    with open(infra_path, "rb") as f:
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
            verify_ssl=proxmox_config.get("verify_ssl", True),
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
        return [vm for vm in vms if regex.search(vm.get("name", ""))]

    def find_vms_by_suffix(self, suffix: str) -> List[Dict[str, Any]]:
        """Find VMs with names ending in a specific suffix."""
        vms = self.get_vms()
        return [vm for vm in vms if vm.get("name", "").endswith(suffix)]

    def find_vm_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a VM by exact name match."""
        vms = self.get_vms()
        for vm in vms:
            if vm.get("name", "") == name:
                return vm
        return None

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
            return status.get("status")
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
        if action not in ("start", "stop"):
            raise ValueError("Action must be 'start' or 'stop'")

        affected_count = 0
        # Search across all nodes, not just the configured one
        for node in self.proxmox.nodes.get():
            node_name = node["node"]
            vms = self.proxmox.nodes(node_name).qemu.get()
            regex = re.compile(pattern)

            for vm in vms:
                vm_name = vm.get("name", "")
                if regex.search(vm_name):
                    vmid = vm["vmid"]
                    current_status = vm.get("status", "unknown")

                    if action == "start" and current_status != "running":
                        if self.proxmox.nodes(node_name).qemu(vmid).status.start.post():
                            logger.info(
                                f"Started VM {vmid} ({vm_name}) on node {node_name}"
                            )
                            affected_count += 1
                    elif action == "stop" and current_status == "running":
                        if self.proxmox.nodes(node_name).qemu(vmid).status.stop.post():
                            logger.info(
                                f"Stopped VM {vmid} ({vm_name}) on node {node_name}"
                            )
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
            node_name = node["node"]
            vms = self.proxmox.nodes(node_name).qemu.get()
            regex = re.compile(pattern)

            for vm in vms:
                vm_name = vm.get("name", "")
                if regex.search(vm_name):
                    vmid = vm["vmid"]
                    logger.info(f"Destroying VM {vmid} ({vm_name}) on node {node_name}")

                    if stop_first and vm.get("status") == "running":
                        logger.info(f"Stopping VM {vmid}...")
                        # Try multiple times to ensure it stops
                        for i in range(3):
                            try:
                                self.proxmox.nodes(node_name).qemu(
                                    vmid
                                ).status.stop.post(skiplock=1)
                                time.sleep(0.25)
                            except Exception as e:
                                logger.warning(
                                    f"Stop attempt {i+1} failed for VM {vmid}: {e}"
                                )

                    try:
                        self.proxmox.nodes(node_name).qemu(vmid).delete(skiplock=1)
                        deleted_count += 1
                        logger.info(f"Deleted VM {vmid} ({vm_name})")
                    except Exception as e:
                        logger.error(f"Failed to delete VM {vmid}: {e}")

        return deleted_count

    def nuke_gateway_vms(self) -> int:
        """Delete all VMs with names ending in '-range-gw'."""
        return self.nuke_by_pattern(r".*-range-gw$")

    def get_vm_mac_addresses(self, vmid: int) -> Dict[str, str]:
        """
        Get MAC addresses from a VM's network interfaces.

        Args:
            vmid: VM ID to get MAC addresses from

        Returns:
            Dict mapping interface names (net0, net1, etc.) to MAC addresses
        """
        mac_addresses = {}
        try:
            config = self.proxmox.nodes(self.node).qemu(vmid).config.get()
            # Look for network interface configurations (net0, net1, net2, etc.)
            for key, value in config.items():
                if key.startswith("net") and isinstance(value, str):
                    # Parse network config string to extract MAC address
                    # Format is typically: "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"
                    parts = value.split(",")
                    for part in parts:
                        if "=" in part:
                            k, v = part.split("=", 1)
                            # Check if this looks like a MAC address
                            if ":" in v and len(v.split(":")) == 6:
                                mac_addresses[key] = v
                                logger.debug(f"Found MAC address for {key}: {v}")
                                break
        except Exception as e:
            logger.error(f"Failed to get MAC addresses for VM {vmid}: {e}")
        return mac_addresses

    def set_vm_mac_addresses(
        self,
        vmid: int,
        mac_addresses: Dict[str, str],
        bridge_name: Optional[str] = None,
    ) -> bool:
        """
        Set MAC addresses on a VM's network interfaces.

        Args:
            vmid: VM ID to set MAC addresses on
            mac_addresses: Dict mapping interface names to MAC addresses
            bridge_name: Optional bridge name to use for all interfaces

        Returns:
            True if successful, False otherwise
        """
        try:
            config = self.proxmox.nodes(self.node).qemu(vmid).config.get()

            for net_interface, mac_address in mac_addresses.items():
                if net_interface in config:
                    # Get the existing network config
                    existing_config = config[net_interface]
                    parts = existing_config.split(",")

                    # Extract the model/type (e.g., "virtio", "e1000")
                    model = parts[0].split("=")[0] if "=" in parts[0] else "virtio"

                    # Build new config with preserved MAC and optionally new bridge
                    new_parts = [f"{model}={mac_address}"]

                    # Add bridge (use provided or extract from existing)
                    if bridge_name:
                        new_parts.append(f"bridge={bridge_name}")
                    else:
                        # Keep existing bridge if present
                        for part in parts:
                            if part.startswith("bridge="):
                                new_parts.append(part)
                                break

                    # Add any other parameters from original config (except old MAC)
                    for part in parts[1:]:
                        if not part.startswith("bridge=") and "=" in part:
                            param_name = part.split("=")[0]
                            # Skip parameters we're already handling
                            if param_name not in ["bridge"]:
                                new_parts.append(part)

                    new_config = ",".join(new_parts)

                    # Update the interface configuration
                    update_params = {net_interface: new_config}
                    self.proxmox.nodes(self.node).qemu(vmid).config.post(
                        **update_params
                    )
                    logger.info(
                        f"Set MAC address for VM {vmid} {net_interface}: {mac_address}"
                    )
            return True
        except Exception as e:
            logger.error(f"Failed to set MAC addresses for VM {vmid}: {e}")
            return False

    def clone_vm(
        self,
        base_vmid: int,
        new_vmid: int,
        name: str,
        pool: Optional[str] = None,
        full_clone: bool = False,
        preserve_mac: bool = False,
    ) -> tuple[bool, Optional[Dict[str, str]]]:
        """
        Clone a VM.

        Args:
            base_vmid: Source VM ID to clone from
            new_vmid: New VM ID for the clone
            name: Name for the new VM
            pool: Optional pool to assign the VM to
            full_clone: Whether to make a full clone (default: linked clone)
            preserve_mac: Whether to preserve MAC addresses from source VM

        Returns:
            Tuple of (success: bool, mac_addresses: Optional[Dict[str, str]])
            - success: True if cloning was successful, False otherwise
            - mac_addresses: Dictionary of preserved MAC addresses if preserve_mac=True, None otherwise
        """
        try:
            # Get MAC addresses before cloning if preservation is requested
            mac_addresses = {}
            if preserve_mac:
                mac_addresses = self.get_vm_mac_addresses(base_vmid)
                logger.info(
                    f"Preserving MAC addresses from VM {base_vmid}: {mac_addresses}"
                )

            clone_params = {
                "newid": new_vmid,
                "name": name,
                "full": 1 if full_clone else 0,
                "target": self.node,
            }

            if pool:
                clone_params["pool"] = pool

            self.proxmox.nodes(self.node).qemu(base_vmid).clone.post(**clone_params)
            logger.info(f"Cloned VM {base_vmid} to {new_vmid} ({name})")

            # Restore MAC addresses after cloning if requested
            # Note: We don't change the bridge here as that will be done by configure_vm_networking
            if preserve_mac and mac_addresses:
                # Small delay to ensure clone operation is complete
                import time

                time.sleep(1)
                self.set_vm_mac_addresses(new_vmid, mac_addresses)

            # Return the MAC addresses so they can be used by configure_vm_networking
            return True, mac_addresses if preserve_mac else None
        except Exception as e:
            logger.error(f"Failed to clone VM {base_vmid} to {new_vmid}: {e}")
            return False, None


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
            return [u for u in users if u["userid"].endswith(f"@{realm_filter}")]
        return users

    def user_exists(self, userid: str) -> bool:
        """Check if a user exists."""
        users = self.get_users()
        return any(user.get("userid") == userid for user in users)

    def validate_ad_user(self, username: str) -> bool:
        """
        Validate that a user exists in the AD realm.

        Args:
            username: Username (without realm)

        Returns:
            True if user exists in AD realm, False otherwise
        """
        userid = f"{username}@ad"
        return self.user_exists(userid)

    def get_ad_user_error_message(self, username: str) -> str:
        """
        Get a helpful error message for when an AD user doesn't exist.

        Args:
            username: Username (without realm)

        Returns:
            Error message instructing to contact admin
        """
        return (
            f"User '{username}@ad' does not exist. "
            f"Please contact an administrator to create the account "
            f"'{username}' on the domain controller."
        )

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
            encoded_userid = urllib.parse.quote(userid, safe="")
            self.proxmox.access.users(encoded_userid).delete()
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
            userid = user.get("userid")
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

    def __init__(self, proxmox: ProxmoxAPI, secrets: Optional[Dict[str, Any]] = None):
        self.proxmox = proxmox
        self.secrets = secrets or load_secrets()

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

    def create_vnet(
        self, vnet_name: str, zone: str, alias: Optional[str] = None
    ) -> bool:
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
            params = {"vnet": vnet_name, "zone": zone}
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

    def ensure_user_vnet(
        self, username: str, zone: Optional[str] = None
    ) -> Optional[str]:
        """
        Ensure a VNet exists for a user.

        This method follows the new strategy:
        1. First check if user already has a VNet assigned
        2. Look for an unassigned VNet (no alias) and assign it
        3. Only create a new VNet if no unassigned ones are available

        Args:
            username: Username to create VNet for
            zone: SDN zone to create VNet in (defaults to value from infra.toml)

        Returns:
            VNet name if successful, None otherwise
        """
        try:
            # Load infrastructure configuration if zone not provided
            if zone is None:
                infra_config = load_infra_config()
                naming_config = infra_config.get("naming", {})
                zone = naming_config.get("vnet_zone", "CMPCCDC")
                vnet_prefix = naming_config.get("vnet_prefix", "RN")
            else:
                vnet_prefix = "RN"  # Default fallback

            # Get existing VNets
            vnets = self.get_vnets()

            # First check if a VNet already exists for this user (by checking alias field)
            for vnet in vnets:
                if vnet.get("alias") == username:
                    existing_vnet_name = vnet.get("vnet")
                    logger.info(
                        f"VNet '{existing_vnet_name}' already exists for user {username}"
                    )
                    return existing_vnet_name

            # Look for an unassigned VNet (one with no alias or empty alias)
            unassigned_vnets = []
            for vnet in vnets:
                vnet_name = vnet.get("vnet", "")
                alias = vnet.get("alias")
                # Check if this VNet matches our naming pattern and has no alias
                if vnet_name.startswith(vnet_prefix) and (
                    not alias or alias.strip() == ""
                ):
                    # Extract number from VNet name to sort properly
                    try:
                        vnet_num = int(vnet_name[len(vnet_prefix) :])
                        unassigned_vnets.append((vnet_num, vnet_name))
                    except ValueError:
                        # Skip VNets that don't follow the expected naming pattern
                        continue

            # Sort unassigned VNets by number and use the lowest available
            if unassigned_vnets:
                unassigned_vnets.sort()  # Sort by number (first element of tuple)
                _, vnet_name = unassigned_vnets[
                    0
                ]  # Get the VNet name from the first tuple

                # Update the VNet to assign it to this user
                try:
                    # Delete and recreate the VNet with the new alias
                    # This is the most reliable way to update the alias in Proxmox
                    if self.delete_vnet(vnet_name):
                        if self.create_vnet(vnet_name, zone, username):
                            logger.info(
                                f"Assigned existing VNet '{vnet_name}' to user {username}"
                            )
                            return vnet_name
                        else:
                            logger.error(
                                f"Failed to recreate VNet {vnet_name} with user alias"
                            )
                    else:
                        logger.error(
                            f"Failed to delete VNet {vnet_name} for reassignment"
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to assign VNet {vnet_name} to user {username}: {e}"
                    )

            # If no unassigned VNets are available, create a new one
            # Generate a unique numeric VNet name RN# format (no zero padding)
            existing_vnet_names = {v.get("vnet", "") for v in vnets}

            # Find the next available number starting from 37 to avoid conflicts with existing RN1-RN36
            for i in range(37, 1000000):  # Support up to 999999 users as requested
                vnet_name = f"{vnet_prefix}{i}"
                if vnet_name not in existing_vnet_names:
                    # Create the new VNet with username in alias field
                    if self.create_vnet(vnet_name, zone, username):
                        logger.info(
                            f"Created new VNet '{vnet_name}' for user {username}"
                        )
                        return vnet_name
                    else:
                        return None

            # If we get here, we couldn't find an available number
            logger.error(f"Could not find available VNet number for user {username}")
            return None

        except Exception as e:
            logger.error(f"Error ensuring VNet for {username}: {e}")
            return None

    def reload_sdn(self) -> bool:
        """Reload SDN configuration using raw requests API."""
        try:
            # Get Proxmox connection details from secrets
            proxmox_config = self.secrets["proxmox"]
            host = proxmox_config["host"]

            # Ensure host doesn't have trailing paths
            if host.endswith("/api2/json"):
                host = host.replace("/api2/json", "")
            if not host.startswith("http"):
                host = f"https://{host}"

            # Get authentication ticket from proxmoxer connection
            # This is a bit of a hack but proxmoxer doesn't expose the ticket easily
            try:
                # Try the standard proxmoxer API first
                self.proxmox.cluster.sdn.reload.post()
                logger.info("Reloaded SDN configuration using proxmoxer")
                return True
            except Exception as proxmoxer_error:
                logger.warning(
                    f"Proxmoxer SDN reload failed: {proxmoxer_error}, trying raw requests"
                )

                # Fall back to raw requests
                auth_url = f"{host}/api2/json/access/ticket"
                auth_data = {
                    "username": proxmox_config["user"],
                    "password": proxmox_config["password"],
                }

                verify_ssl = proxmox_config.get("verify_ssl", True)

                # Get authentication ticket
                auth_response = requests.post(
                    auth_url, data=auth_data, verify=verify_ssl, timeout=30
                )
                auth_response.raise_for_status()
                auth_data = auth_response.json()["data"]

                # Prepare headers for authenticated request
                headers = {"CSRFPreventionToken": auth_data["CSRFPreventionToken"]}
                cookies = {"PVEAuthCookie": auth_data["ticket"]}

                # Make the SDN reload request
                reload_url = f"{host}/api2/json/cluster/sdn/reload"
                reload_response = requests.post(
                    reload_url,
                    headers=headers,
                    cookies=cookies,
                    verify=verify_ssl,
                    timeout=30,
                )
                reload_response.raise_for_status()

                logger.info("Reloaded SDN configuration using raw requests API")
                return True

        except Exception as e:
            logger.error(f"Failed to reload SDN configuration: {e}")
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
        return any(p["poolid"] == pool_name for p in pools)

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
        self.networks = NetworkManager(self.proxmox, secrets)
        self.pools = PoolManager(self.proxmox)

    def user_has_complete_range(
        self, username: str, pool_suffix: Optional[str] = None
    ) -> bool:
        """
        Check if a user already has a complete range setup.

        This checks for:
        - User pool exists
        - User VNet exists
        - VyOS gateway VM exists with correct name and is in user's pool

        Args:
            username: Username (without realm)
            pool_suffix: Suffix for the pool name (defaults to value from infra.toml)

        Returns:
            True if user has complete setup, False otherwise
        """
        try:
            # Load infrastructure configuration if pool_suffix not provided
            if pool_suffix is None:
                infra_config = load_infra_config()
                naming_config = infra_config.get("naming", {})
                pool_suffix = naming_config.get("pool_suffix", "-range")
                vyos_suffix = naming_config.get("vyos_suffix", "-range-vyos")
            else:
                vyos_suffix = "-range-vyos"  # Default fallback

            pool_name = f"{username}{pool_suffix}"
            vyos_name = f"{username}{vyos_suffix}"

            # Check if pool exists
            if not self.pools.pool_exists(pool_name):
                logger.debug(f"Pool {pool_name} doesn't exist for {username}")
                return False

            # Check if VNet exists (this also returns the name if it exists)
            vnet_name = self.networks.ensure_user_vnet(username)
            if not vnet_name:
                logger.debug(f"VNet doesn't exist for {username}")
                return False

            # Check if VyOS gateway VM exists
            vyos_vm = self.vms.find_vm_by_name(vyos_name)
            if not vyos_vm:
                logger.debug(f"VyOS gateway VM {vyos_name} doesn't exist")
                return False

            # Verify the VM is in the correct pool
            vmid = vyos_vm["vmid"]
            try:
                # Get VM config to check pool assignment
                vm_config = self.proxmox.nodes(self.node).qemu(vmid).config.get()
                vm_pool = vm_config.get("pool")
                if vm_pool != pool_name:
                    logger.debug(
                        f"VyOS VM {vmid} is in pool {vm_pool}, expected {pool_name}"
                    )
                    return False
            except Exception as e:
                logger.warning(f"Could not verify pool for VM {vmid}: {e}")
                # Don't fail completely if we can't check the pool, but log it

            logger.info(f"User {username} already has complete range setup")
            return True

        except Exception as e:
            logger.error(f"Error checking complete range for {username}: {e}")
            return False

    def setup_user_range(
        self,
        username: str,
        base_vmid: Optional[int] = None,
        pool_suffix: Optional[str] = None,
    ) -> bool:
        """
        Set up a complete range environment for a user.

        This includes:
        - Validating user exists in AD realm
        - Creating a dedicated pool
        - Setting up a VNet
        - Cloning a gateway VM
        - Setting appropriate permissions

        Args:
            username: Username (without realm)
            base_vmid: Base VM ID to clone from (defaults to value from infra.toml)
            pool_suffix: Suffix for the pool name (defaults to value from infra.toml)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Load infrastructure configuration
            infra_config = load_infra_config()
            naming_config = infra_config.get("naming", {})
            networking_config = infra_config.get("networking", {})

            # Use provided parameters or fall back to config defaults
            if pool_suffix is None:
                pool_suffix = naming_config.get("pool_suffix", "-range")
            if base_vmid is None:
                base_vmid = networking_config.get("vyos_base_vmid", 150)

            # Validate user exists in AD realm first
            if not self.users.validate_ad_user(username):
                logger.error(self.users.get_ad_user_error_message(username))
                return False

            # Check if user already has complete range setup
            if self.user_has_complete_range(username, pool_suffix):
                logger.info(
                    f"User {username} already has complete range setup, skipping"
                )
                return True

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
            vyos_suffix = naming_config.get("vyos_suffix", "-range-vyos")
            clone_name = f"{username}{vyos_suffix}"

            # Clone the gateway VM
            success, _ = self.vms.clone_vm(base_vmid, new_vmid, clone_name, pool_name)
            if not success:
                return False

            # Configure networking for the cloned VM
            self.configure_gateway_networking(new_vmid, vnet_name)

            # Set user permissions
            self._set_user_permissions(f"{username}@ad", pool_name, new_vmid)

            logger.info(f"Successfully set up range for {username}@ad")
            return True

        except Exception as e:
            logger.error(f"Failed to setup range for {username}: {e}")
            return False

    def configure_gateway_networking(self, vmid: int, vnet_name: str):
        """Configure networking for a cloned gateway VM."""
        try:
            # Load infrastructure configuration
            infra_config = load_infra_config()
            networking_config = infra_config.get("networking", {})

            # Get network configuration from infra.toml
            infranet_bridge = networking_config.get("infranet_bridge", "INFRANET")
            net0_type = networking_config.get("net0_type", "virtio")
            net1_type = networking_config.get("net1_type", "virtio")

            # Set net0 to infrastructure network and net1 to user's VNet
            net0 = f"{net0_type},bridge={infranet_bridge}"
            net1 = f"{net1_type},bridge={vnet_name}"

            self.proxmox.nodes(self.node).qemu(vmid).config.post(net0=net0)
            self.proxmox.nodes(self.node).qemu(vmid).config.post(net1=net1)

            logger.info(
                f"Configured gateway networking for VM {vmid} with VNet {vnet_name}"
            )
        except Exception as e:
            logger.error(f"Failed to configure gateway networking for VM {vmid}: {e}")

    def configure_vm_networking(
        self,
        vmid: int,
        vnet_name: str,
        preserve_mac: bool = False,
        template_mac_addresses: Optional[Dict[str, str]] = None,
    ):
        """Configure networking for a non-gateway VM (set net0 to user's VNet).

        Args:
            vmid: VM ID to configure
            vnet_name: VNet bridge name
            preserve_mac: Whether to preserve MAC addresses
            template_mac_addresses: MAC addresses from template VM (used when preserve_mac=True)
        """
        try:
            net0_type = "e1000"

            if (
                preserve_mac
                and template_mac_addresses
                and "net0" in template_mac_addresses
            ):
                # Use MAC address from template VM
                mac_address = template_mac_addresses["net0"]
                net0 = f"{net0_type}={mac_address},bridge={vnet_name}"
                logger.info(
                    f"Configuring VM {vmid} with preserved MAC from template: {mac_address}"
                )
            else:
                # Standard configuration without MAC preservation
                net0 = f"{net0_type},bridge={vnet_name}"
                if preserve_mac and not template_mac_addresses:
                    logger.warning(
                        f"MAC preservation requested for VM {vmid} but no template MAC addresses provided"
                    )

            self.proxmox.nodes(self.node).qemu(vmid).config.post(net0=net0)

            logger.info(f"Configured networking for VM {vmid} with VNet {vnet_name}")
        except Exception as e:
            logger.error(f"Failed to configure networking for VM {vmid}: {e}")

    def _set_user_permissions(self, userid: str, pool_name: str, vmid: int):
        """Set user permissions on pool and VM."""
        try:
            # Set permissions on pool
            self.proxmox.access.acl.put(
                path=f"/pool/{pool_name}", users=userid, roles="Administrator,PVEAdmin"
            )

            # Set permissions on VM
            self.proxmox.access.acl.put(
                path=f"/vms/{vmid}", users=userid, roles="Administrator,PVEAdmin"
            )

            logger.info(
                f"Set permissions for {userid} on pool {pool_name} and VM {vmid}"
            )
        except Exception as e:
            logger.error(f"Failed to set permissions for {userid}: {e}")
