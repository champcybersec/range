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
import urllib3
from typing import Dict, List, Any, Optional, Tuple
from proxmoxer import ProxmoxAPI
import logging

logger = logging.getLogger(__name__)


def build_resource_prefix(username: str, club: Optional[str] = None) -> str:
    """
    Build the standard resource prefix using optional club identifier.

    Args:
        username: Base username (without realm)
        club: Optional club identifier (e.g., 'CCDC')

    Returns:
        Combined prefix such as 'CCDC/jane.doe' or 'jane.doe' if no club provided.
    """
    username_clean = (username or "").strip()
    club_clean = (club or "").strip()

    if club_clean:
        return f"{club_clean.upper()}/{username_clean}"

    return username_clean


_DNS_SANITIZE_PATTERN = re.compile(r"[^A-Za-z0-9\-\.]+")


def build_dns_safe_name(*parts: str) -> str:
    """
    Build a DNS-safe name by combining parts and normalizing disallowed characters.

    Args:
        *parts: Substrings to combine into a DNS-safe label.

    Returns:
        Lowercase DNS-safe string where invalid characters are replaced with hyphens.

    Raises:
        ValueError: If the resulting name would be empty.
    """
    combined = "-".join(part.strip() for part in parts if part and part.strip())
    sanitized = _DNS_SANITIZE_PATTERN.sub("-", combined)
    sanitized = re.sub(r"-{2,}", "-", sanitized).strip("-.")

    if not sanitized:
        raise ValueError("Cannot build DNS-safe name from empty parts")

    return sanitized.lower()


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


def resolve_template_label(
    template_vmid: int,
    templates: Optional[Dict[str, str]] = None,
) -> str:
    """
    Resolve a human-friendly label for a VM template.

    Args:
        template_vmid: VMID of the template
        templates: Optional mapping of VMID -> label (avoids reloading TOML)

    Returns:
        Label for the template, or a fallback string if not found.
    """
    vmid_key = str(template_vmid)

    if templates and vmid_key in templates:
        return templates[vmid_key]

    if templates is None:
        try:
            templates = load_vmids()
            if vmid_key in templates:
                return templates[vmid_key]
        except Exception as exc:
            logger.debug(
                "Could not load VM template labels for VMID %s: %s",
                template_vmid,
                exc,
            )

    return f"range-{template_vmid}"


def build_vm_clone_name(
    username: str,
    template_vmid: int,
    club: Optional[str] = None,
    templates: Optional[Dict[str, str]] = None,
) -> str:
    """
    Build the display name for a cloned VM using username, club, and template name.

    Args:
        username: Base username without realm
        template_vmid: ID of the template being cloned
        club: Optional club identifier (e.g., 'CCDC')
        templates: Optional mapping of VMID -> template label to avoid reloads

    Returns:
        DNS-safe VM name following the pattern username-club-template.
    """
    template_label = resolve_template_label(template_vmid, templates)
    # The helper filters out empty parts automatically.
    return build_dns_safe_name(username, club, template_label)


def build_gateway_clone_name(
    username: str,
    club: Optional[str] = None,
    naming_config: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the standard gateway VM name using optional club context.

    Args:
        username: Base username without realm
        club: Optional club identifier (e.g., 'CCDC')
        naming_config: Optional naming configuration (e.g., from infra.toml)

    Returns:
        DNS-safe gateway VM name. Pattern defaults to:
            <club>-range-gateway-<username>
        if a club is provided, otherwise:
            range-gateway-<username>
    """
    label = "range-gateway"
    if naming_config:
        candidate = (
            naming_config.get("gateway_label")
            or naming_config.get("gateway_name")
            or naming_config.get("vyos_suffix")
        )
        if candidate:
            candidate_str = str(candidate).strip()
            # Strip legacy leading hyphens (e.g., "-range-vyos")
            candidate_str = candidate_str.lstrip("-")
            # Normalize legacy values to the new gateway naming
            if candidate_str.lower() in {"range-vyos", "vyos"}:
                candidate_str = "range-gateway"
            if candidate_str:
                label = candidate_str

    return build_dns_safe_name(club, label, username)


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
    verify_ssl = proxmox_config.get("verify_ssl", False)

    # Clean up host URL for proxmoxer
    if host.endswith("/api2/json"):
        host = host.replace("/api2/json", "")

    # Suppress SSL warnings if SSL verification is disabled
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.debug("SSL verification disabled - suppressing SSL warnings")

    logger.debug(f"Connecting to Proxmox at {host} as {proxmox_config['user']}")

    try:
        return ProxmoxAPI(
            host,
            user=proxmox_config["user"],
            password=proxmox_config["password"],
            verify_ssl=verify_ssl,
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
        """Delete all gateway VMs (legacy '-range-gw' or new '-range-gateway')."""
        return self.nuke_by_pattern(r".*-range-gw(?:ateway)?$")

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

    @staticmethod
    def _normalize_identity(username: str, club: Optional[str] = None) -> Optional[str]:
        """
        Normalize usernames (and optional club identifiers) for comparisons.

        Returns lowercase strings suitable for equality checks or None if username empty.
        """
        username_clean = (username or "").strip().lower()
        if not username_clean:
            return None

        club_clean = (club or "").strip().lower()
        if club_clean:
            return f"{club_clean}/{username_clean}"

        return username_clean

    @staticmethod
    def _build_alias(username: str, club: Optional[str] = None) -> str:
        """
        Build the display alias stored on the VNet (preserves username case, uppercases club).
        """
        return build_resource_prefix(username, club)

    @staticmethod
    def _legacy_identity_variants(
        username: str, club: Optional[str] = None
    ) -> List[str]:
        """
        Provide legacy identity keys for backward compatibility.

        This currently includes:
        - Username without club prefix
        - Club prefixed with hyphen separator (old format)
        """
        variants: List[str] = []
        username_only = NetworkManager._normalize_identity(username)
        if username_only:
            variants.append(username_only)

        club_clean = (club or "").strip().lower()
        username_clean = (username or "").strip().lower()

        if club_clean and username_clean:
            variants.append(f"{club_clean}-{username_clean}")  # Previous format

        return variants

    def get_vnets(self) -> List[Dict[str, Any]]:
        """Get list of all VNets."""
        try:
            return self.proxmox.cluster.sdn.vnets.get()
        except Exception as e:
            logger.error(f"Failed to get VNets: {e}")
            return []

    def get_vnet_for_user(
        self, username: str, club: Optional[str] = None
    ) -> Optional[str]:
        """
        Get the VNet assigned to a specific user.

        Args:
            username: Username to look up
            club: Optional club identifier to disambiguate users belonging to multiple clubs

        Returns:
            VNet name if found, None otherwise
        """
        try:
            vnets = self.get_vnets()
            target_key = self._normalize_identity(username, club)

            # Don't match empty usernames
            if not target_key:
                logger.debug("Empty username provided, returning None")
                return None

            # When club is supplied, also keep track of the legacy alias for fallback
            fallback_keys: List[str] = []
            if club is not None:
                fallback_keys = self._legacy_identity_variants(username, club)

            for vnet in vnets:
                alias = vnet.get("alias", "")
                # Normalize alias for comparison (lowercase and strip whitespace)
                normalized_alias = alias.strip().lower()

                # Use exact match after normalization to avoid partial matches
                if normalized_alias and normalized_alias == target_key:
                    vnet_name = vnet.get("vnet")
                    logger.debug(
                        f"Found VNet '{vnet_name}' for user '{username}' "
                        f"(matched alias '{alias}')"
                    )
                    return vnet_name

            # Fallback to legacy alias if requested and available
            if fallback_keys:
                for vnet in vnets:
                    alias = vnet.get("alias", "")
                    normalized_alias = alias.strip().lower()
                    if normalized_alias and normalized_alias in fallback_keys:
                        vnet_name = vnet.get("vnet")
                        logger.debug(
                            f"Found legacy VNet '{vnet_name}' for user '{username}' "
                            f"(matched alias '{alias}')"
                        )
                        return vnet_name

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

    def clear_all_vnet_aliases(
        self, dry_run: bool = False, exclude: Optional[List[str]] = None
    ) -> Tuple[int, List[str]]:
        """
        Clear alias/description labels from all managed VNets, respecting exclusions.

        Args:
            dry_run: If True, logs planned changes without applying them.
            exclude: Optional list of case-insensitive substrings. If any value matches
                     the VNet's alias or description, that VNet will be skipped.

        Returns:
            Tuple containing (count of VNets processed, list of VNets that failed to update).
        """
        vnets = self.get_vnets()
        cleared_count = 0
        failed: List[str] = []
        normalized_excludes = [
            pattern.strip().lower()
            for pattern in (exclude or [])
            if pattern and pattern.strip()
        ]

        for vnet in vnets:
            alias = (vnet.get("alias") or "").strip()
            description = (vnet.get("description") or "").strip()
            legacy_description = (vnet.get("descr") or "").strip()

            if not alias:
                continue

            vnet_name = (vnet.get("vnet") or "").strip()
            zone = vnet.get("zone")

            if not vnet_name or not zone:
                logger.warning(
                    f"Skipping VNet with insufficient data: name='{vnet_name}', zone='{zone}'"
                )
                continue

            if not re.fullmatch(r"RN\d+", vnet_name):
                logger.info(
                    f"Skipping unmanaged VNet '{vnet_name}' in zone '{zone}' while clearing aliases"
                )
                continue

            if normalized_excludes:
                labels = [alias]
                if description:
                    labels.append(description)
                if legacy_description and legacy_description not in labels:
                    labels.append(legacy_description)

                matched_pattern: Optional[str] = None
                matched_label: Optional[str] = None

                for label in labels:
                    lower_label = label.lower()
                    for pattern in normalized_excludes:
                        if pattern in lower_label:
                            matched_pattern = pattern
                            matched_label = label
                            break
                    if matched_pattern:
                        break

                if matched_pattern:
                    logger.info(
                        f"Skipping VNet '{vnet_name}' in zone '{zone}' while clearing aliases "
                        f"(label '{matched_label}' matched exclude value '{matched_pattern}')"
                    )
                    continue

            if dry_run:
                logger.info(
                    f"[DRYRUN] Would clear alias '{alias}' from VNet '{vnet_name}'"
                )
                cleared_count += 1
                continue

            try:
                self.proxmox.cluster.sdn.vnets(vnet_name).put(zone=zone, alias="")
                logger.info(
                    f"Cleared alias '{alias}' from VNet '{vnet_name}' in zone '{zone}'"
                )
                cleared_count += 1
            except Exception as e:
                logger.error(f"Failed to clear alias for VNet '{vnet_name}': {e}")
                failed.append(vnet_name)

        return cleared_count, failed

    def ensure_user_vnet(
        self, username: str, zone: Optional[str] = None, club: Optional[str] = None
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
            club: Optional club identifier to scope the VNet

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

            # Normalize username for comparison (lowercase and strip whitespace)
            normalized_target = self._normalize_identity(username, club)

            # Don't proceed with empty usernames
            if not normalized_target:
                logger.error("Empty username provided to ensure_user_vnet")
                return None

            desired_alias = self._build_alias(username, club)
            fallback_keys: List[str] = []
            if club is not None:
                fallback_keys = self._legacy_identity_variants(username, club)

            # First check if a VNet already exists for this user (by checking alias field)
            for vnet in vnets:
                alias = vnet.get("alias", "")
                # Normalize alias for comparison (lowercase and strip whitespace)
                normalized_alias = alias.strip().lower()

                # Use exact match after normalization to avoid partial matches
                if normalized_alias and normalized_alias == normalized_target:
                    existing_vnet_name = vnet.get("vnet")
                    logger.info(
                        f"VNet '{existing_vnet_name}' already exists for user {username}"
                        f"{f' (club {club})' if club else ''} (matched alias '{alias}')"
                    )
                    return existing_vnet_name
                if normalized_alias and normalized_alias in fallback_keys:
                    existing_vnet_name = vnet.get("vnet")
                    logger.info(
                        f"VNet '{existing_vnet_name}' already exists for user {username}"
                        f"{f' (club {club})' if club else ''} using legacy alias '{alias}'"
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
                        if self.create_vnet(vnet_name, zone, desired_alias):
                            logger.info(
                                f"Assigned existing VNet '{vnet_name}' to user {username}"
                                f"{f' (club {club})' if club else ''}"
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
                    if self.create_vnet(vnet_name, zone, desired_alias):
                        logger.info(
                            f"Created new VNet '{vnet_name}' for user {username}"
                            f"{f' (club {club})' if club else ''}"
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

                verify_ssl = proxmox_config.get("verify_ssl", False)

                # Suppress SSL warnings if SSL verification is disabled
                if not verify_ssl:
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    def __init__(
        self,
        proxmox: ProxmoxAPI,
        secrets: Optional[Dict[str, Any]] = None,
        vm_manager: Optional["VMManager"] = None,
    ):
        self.proxmox = proxmox
        self.secrets = secrets
        self.vm_manager = vm_manager

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

    def delete_pool(self, pool_name: str) -> bool:
        """
        Delete a pool by name.

        Args:
            pool_name: Pool identifier to delete

        Returns:
            True if deletion succeeded, False otherwise
        """
        if not self._delete_pool_members(pool_name):
            logger.error(
                "Aborting deletion of pool %s because member cleanup failed", pool_name
            )
            return False

        try:
            self.proxmox.pools.delete(poolid=pool_name)
            logger.info(f"Deleted pool: {pool_name}")
            return True
        except Exception as e:
            logger.warning(
                f"Standard delete failed for pool {pool_name}: {e}. "
                "Attempting raw API fallback."
            )
            if "/" in pool_name and self._delete_pool_via_http(pool_name):
                return True
            logger.error(f"Failed to delete pool {pool_name}: {e}")
            return False

    def find_pools_by_pattern(self, pattern: str) -> List[str]:
        """
        Find pool IDs that match a regex pattern, excluding protected pools.

        Args:
            pattern: Regex pattern to evaluate against pool IDs

        Returns:
            List of matching pool IDs (protected pools omitted)
        """
        regex = re.compile(pattern)
        matches: List[str] = []
        for pool in self.get_pools():
            pool_id = pool.get("poolid", "")
            if not pool_id:
                continue

            if not regex.search(pool_id):
                continue

            # Skip protected pools containing 'prod' or 'infra'
            lowered = pool_id.lower()
            if "prod" in lowered or "infra" in lowered:
                logger.debug(f"Skipping protected pool {pool_id}")
                continue

            matches.append(pool_id)
        return matches

    def nuke_pools_by_pattern(
        self, pattern: str, dry_run: bool = False
    ) -> Tuple[List[str], List[str]]:
        """
        Delete pools that match a regex pattern, with safety exclusions.

        Args:
            pattern: Regex pattern to match pool IDs
            dry_run: If True, do not delete pools

        Returns:
            Tuple of (matched pool IDs, successfully deleted pool IDs)
        """
        matches = self.find_pools_by_pattern(pattern)
        if dry_run:
            return matches, []

        deleted: List[str] = []
        for pool_id in matches:
            if self.delete_pool(pool_id):
                deleted.append(pool_id)

        return matches, deleted

    def _delete_pool_via_http(self, pool_name: str) -> bool:
        """Fallback deletion using direct HTTP requests for slash-containing pool IDs."""
        if not self.secrets:
            logger.debug("No secrets provided; cannot perform raw pool deletion.")
            return False

        proxmox_config = self.secrets.get("proxmox", {})
        host = proxmox_config.get("host")
        user = proxmox_config.get("user")
        password = proxmox_config.get("password")

        if not (host and user and password):
            logger.error(
                "Incomplete Proxmox configuration; cannot perform raw pool deletion."
            )
            return False

        verify_ssl = proxmox_config.get("verify_ssl", False)

        if host.endswith("/api2/json"):
            host = host.replace("/api2/json", "")
        parsed = urllib.parse.urlparse(host if host.startswith("http") else f"https://{host}")
        scheme = parsed.scheme or "https"
        hostname = parsed.hostname or parsed.path  # urlparse puts bare host in path
        port = parsed.port
        if port is None:
            port = 8006 if scheme == "https" else 80
        host = f"{scheme}://{hostname}:{port}"

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            auth_url = f"{host}/api2/json/access/ticket"
            auth_response = requests.post(
                auth_url,
                data={"username": user, "password": password},
                verify=verify_ssl,
                timeout=30,
            )
            auth_response.raise_for_status()
            auth_data = auth_response.json()["data"]

            headers = {"CSRFPreventionToken": auth_data["CSRFPreventionToken"]}
            cookies = {"PVEAuthCookie": auth_data["ticket"]}

            delete_url = f"{host}/api2/json/pools"

            delete_response = requests.delete(
                delete_url,
                headers=headers,
                cookies=cookies,
                params={"poolid": pool_name},
                verify=verify_ssl,
                timeout=30,
            )
            delete_response.raise_for_status()
            logger.info(
                "Deleted pool %s using raw HTTP request (fallback path)", pool_name
            )
            return True
        except Exception as raw_error:
            logger.error(f"Raw HTTP pool deletion failed for {pool_name}: {raw_error}")
            return False

    def _delete_pool_members(self, pool_name: str) -> bool:
        """
        Ensure all VMs in the pool are stopped and deleted before removing the pool.

        Returns True if cleanup succeeded or there were no VMs to delete.
        """
        members = self._get_pool_members(pool_name)
        if not members:
            return True

        if not self.vm_manager:
            logger.warning(
                "Pool %s has %d members but no VM manager is available for cleanup",
                pool_name,
                len(members),
            )
            return False

        failures: List[int] = []

        for member in members:
            vmid = member.get("vmid")
            if vmid is None:
                continue

            # Stop VM (force to avoid wait) then delete
            try:
                self.vm_manager.stop_vm(vmid, force=True)
                if not self.vm_manager.delete_vm(vmid, force=True):
                    failures.append(vmid)
            except Exception as exc:
                logger.error(
                    "Encountered exception while deleting VM %s from pool %s: %s",
                    vmid,
                    pool_name,
                    exc,
                )
                failures.append(vmid)

        if failures:
            logger.error(
                "Failed to delete VMs %s contained in pool %s",
                ", ".join(str(vmid) for vmid in failures),
                pool_name,
            )
            return False

        return True

    def _get_pool_members(self, pool_name: str) -> List[Dict[str, Any]]:
        """Return VM members of a pool."""
        try:
            pool_detail = self.proxmox.pools.get(poolid=pool_name)
        except Exception as e:
            logger.warning(f"Unable to retrieve members for pool {pool_name}: {e}")
            return []

        if isinstance(pool_detail, list):
            target = next(
                (item for item in pool_detail if item.get("poolid") == pool_name),
                (pool_detail[0] if pool_detail else {}),
            )
        else:
            target = pool_detail

        members = target.get("members") or []
        vm_members: List[Dict[str, Any]] = []
        for member in members:
            member_type = (member.get("type") or "").lower()
            if member_type in {"qemu", "vm"} and member.get("vmid") is not None:
                vm_members.append(member)

        return vm_members


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
        self.pools = PoolManager(self.proxmox, secrets, self.vms)

    def user_has_complete_range(
        self,
        username: str,
        pool_suffix: Optional[str] = None,
        club: Optional[str] = None,
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
            resource_prefix = build_resource_prefix(username, club)

            # Load infrastructure configuration if pool_suffix not provided
            infra_config = load_infra_config()
            naming_config = infra_config.get("naming", {})
            if pool_suffix is None:
                pool_suffix = naming_config.get("pool_suffix", "-range")

            pool_name = f"{resource_prefix}{pool_suffix}"

            gateway_name_candidates = [
                build_gateway_clone_name(username, club, naming_config)
            ]

            # Include legacy naming patterns for backward compatibility
            legacy_suffixes = []
            config_suffix = naming_config.get("vyos_suffix")
            if config_suffix:
                legacy_suffixes.append(str(config_suffix))
            legacy_suffixes.append("-range-vyos")

            for suffix in legacy_suffixes:
                if not suffix:
                    continue
                legacy_name = build_dns_safe_name(resource_prefix, suffix)
                gateway_name_candidates.append(legacy_name)

            seen_names: List[str] = []
            for candidate in gateway_name_candidates:
                if candidate not in seen_names:
                    seen_names.append(candidate)

            vyos_vm = None
            vyos_name = ""
            for candidate in seen_names:
                vyos_vm = self.vms.find_vm_by_name(candidate)
                if vyos_vm:
                    vyos_name = candidate
                    break

            # Check if pool exists
            if not self.pools.pool_exists(pool_name):
                logger.debug(
                    f"Pool {pool_name} doesn't exist for {username}"
                    f"{f' (club {club})' if club else ''}"
                )
                return False

            # Check if VNet exists (this also returns the name if it exists)
            vnet_name = self.networks.ensure_user_vnet(username, club=club)
            if not vnet_name:
                logger.debug(
                    f"VNet doesn't exist for {username}"
                    f"{f' (club {club})' if club else ''}"
                )
                return False

            # Check if VyOS gateway VM exists
            if not vyos_vm:
                if seen_names:
                    expected = ", ".join(seen_names)
                    logger.debug(
                        "VyOS gateway VM not found for %s%s. " "Tried names: %s",
                        username,
                        f" (club {club})" if club else "",
                        expected,
                    )
                else:
                    logger.debug(
                        f"VyOS gateway VM doesn't exist for {username}"
                        f"{f' (club {club})' if club else ''}"
                    )
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

            logger.info(
                f"User {username} already has complete range setup"
                f"{f' for club {club}' if club else ''}"
            )
            return True

        except Exception as e:
            logger.error(
                f"Error checking complete range for {username}"
                f"{f' (club {club})' if club else ''}: {e}"
            )
            return False

    def setup_user_range(
        self,
        username: str,
        base_vmid: Optional[int] = None,
        pool_suffix: Optional[str] = None,
        club: Optional[str] = None,
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
            club: Optional club identifier to scope resources

        Returns:
            True if successful, False otherwise
        """
        try:
            resource_prefix = build_resource_prefix(username, club)

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
            if self.user_has_complete_range(username, pool_suffix, club):
                logger.info(
                    f"User {username}{f' (club {club})' if club else ''} already has complete range setup, skipping"
                )
                return True

            pool_name = f"{resource_prefix}{pool_suffix}"

            # Ensure pool exists
            if not self.pools.ensure_pool(pool_name):
                return False

            # Ensure VNet exists
            vnet_name = self.networks.ensure_user_vnet(username, club=club)
            if not vnet_name:
                logger.error(f"Failed to ensure VNet for {username}")
                return False

            # Get next available VM ID
            new_vmid = self.proxmox.cluster.nextid.get()
            clone_name = build_gateway_clone_name(username, club, naming_config)

            # Clone the gateway VM
            success, _ = self.vms.clone_vm(base_vmid, new_vmid, clone_name, pool_name)
            if not success:
                return False

            # Configure networking for the cloned VM
            self.configure_gateway_networking(new_vmid, vnet_name)

            # Set user permissions
            self._set_user_permissions(f"{username}@ad", pool_name, new_vmid)

            logger.info(
                f"Successfully set up range for {username}@ad"
                f"{f' (club {club})' if club else ''}"
            )
            return True

        except Exception as e:
            logger.error(
                f"Failed to setup range for {username}"
                f"{f' (club {club})' if club else ''}: {e}"
            )
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
        retrowin: bool = False,
        template_vmid: Optional[int] = None,
    ):
        """Configure networking for a non-gateway VM (set net0 to user's VNet).

        Args:
            vmid: VM ID to configure
            vnet_name: VNet bridge name
            preserve_mac: Whether to preserve MAC addresses
            template_mac_addresses: MAC addresses from template VM (used when preserve_mac=True)
            retrowin: Whether to use rtl8139 interface type instead of e1000 (for retro Windows VMs)
            template_vmid: VMID of the template being cloned (to preserve interface type)
        """
        try:
            # Determine interface type
            if retrowin:
                net0_type = "rtl8139"
            elif preserve_mac:
                net0_type = "e1000"
            elif template_vmid is not None:
                # Try to get the interface type from the template VM
                config = self.proxmox.nodes(self.node).qemu(template_vmid).config.get()
                net0_config = config.get("net0", "")
                # Extract type (e.g., "virtio", "e1000", etc.)
                net0_type = (
                    net0_config.split("=")[0] if "=" in net0_config else "virtio"
                )
            else:
                net0_type = "virtio"

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

            logger.info(
                f"Configured networking for VM {vmid} with VNet {vnet_name} and interface type {net0_type}"
            )
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
