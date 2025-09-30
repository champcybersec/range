#!/usr/bin/env python3
"""
Proxmox Range CLI Tool

Unified command-line interface for managing Proxmox ranges for competitive cyber training.
This replaces the individual scripts in the scripts/ directory with a single, consistent interface.

Usage:
    python range_cli.py <command> [options]

Commands:
    vm          VM management operations
    user        User management operations
    network     Network/VNet management operations
    range       High-level range setup operations

Use --help with any command for detailed options.
"""

import argparse
import sys
import csv
import os
from typing import List, Optional
import logging

from rangemgr import RangeManager, load_secrets, load_infra_config

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def setup_vm_commands(subparsers):
    """Set up VM management commands."""
    vm_parser = subparsers.add_parser("vm", help="VM management operations")
    vm_subparsers = vm_parser.add_subparsers(dest="vm_command", help="VM commands")

    # VM list
    list_parser = vm_subparsers.add_parser("list", help="List VMs")
    list_parser.add_argument("--pattern", help="Filter VMs by name pattern (regex)")

    # VM power control
    power_parser = vm_subparsers.add_parser("power", help="Start/stop VMs by pattern")
    power_parser.add_argument(
        "action", choices=["start", "stop"], help="Action to perform"
    )
    power_parser.add_argument("pattern", help="Regex pattern to match VM names")

    # VM deletion
    nuke_parser = vm_subparsers.add_parser("nuke", help="Delete VMs by pattern")
    nuke_parser.add_argument("pattern", help="Regex pattern to match VM names")
    nuke_parser.add_argument(
        "--no-stop", action="store_true", help="Don't stop VMs before deletion"
    )
    nuke_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without doing it",
    )

    # Nuke gateway VMs specifically
    nuke_gw_parser = vm_subparsers.add_parser(
        "nuke-gw", help="Delete all gateway VMs (ending in -range-gw)"
    )
    nuke_gw_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be deleted"
    )

    # Clone VM
    clone_parser = vm_subparsers.add_parser("clone", help="Clone a VM")
    clone_parser.add_argument("base_vmid", type=int, help="Source VM ID")
    clone_parser.add_argument("name", help="Name for new VM")
    clone_parser.add_argument("--pool", help="Pool to assign VM to")
    clone_parser.add_argument(
        "--full", action="store_true", help="Create full clone instead of linked"
    )


def setup_user_commands(subparsers):
    """Set up user management commands."""
    user_parser = subparsers.add_parser("user", help="User management operations")
    user_subparsers = user_parser.add_subparsers(
        dest="user_command", help="User commands"
    )

    # List users
    list_parser = user_subparsers.add_parser("list", help="List users")
    list_parser.add_argument("--realm", help="Filter by realm (ad, pve, etc.)")

    # Delete user
    delete_parser = user_subparsers.add_parser("delete", help="Delete a user")
    delete_parser.add_argument(
        "userid", help="Full user ID including realm (e.g., user@ad)"
    )

    # Purge PVE users
    purge_parser = user_subparsers.add_parser(
        "purge-pve", help="Delete all @pve realm users"
    )
    purge_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be deleted"
    )

    # Validate AD user
    validate_parser = user_subparsers.add_parser(
        "validate", help="Validate that a user exists in AD realm"
    )
    validate_parser.add_argument(
        "username", help="Username (without realm) to validate"
    )


def setup_network_commands(subparsers):
    """Set up network management commands."""
    net_parser = subparsers.add_parser(
        "network", help="Network/VNet management operations"
    )
    net_subparsers = net_parser.add_subparsers(
        dest="net_command", help="Network commands"
    )

    # List VNets
    list_parser = net_subparsers.add_parser("list", help="List VNets")

    # Create VNet
    create_parser = net_subparsers.add_parser("create", help="Create a VNet")
    create_parser.add_argument("name", help="VNet name")
    create_parser.add_argument("zone", help="SDN zone")
    create_parser.add_argument("--alias", help="VNet alias")

    # Delete VNet
    delete_parser = net_subparsers.add_parser("delete", help="Delete a VNet")
    delete_parser.add_argument("name", help="VNet name to delete")

    # Ensure user VNet
    ensure_parser = net_subparsers.add_parser(
        "ensure-user", help="Ensure VNet exists for user"
    )
    ensure_parser.add_argument("username", help="Username to create VNet for")
    ensure_parser.add_argument(
        "--zone", default="CMPCCDC", help="SDN zone (default: CMPCCDC)"
    )

    # Ensure VNets for all AD users
    ensure_all_parser = net_subparsers.add_parser(
        "ensure-all", help="Ensure VNets for all AD users"
    )
    ensure_all_parser.add_argument(
        "--zone", default="CMPCCDC", help="SDN zone (default: CMPCCDC)"
    )

    # Pre-create VNets
    prep_parser = net_subparsers.add_parser(
        "pre-prep", help="Pre-create VNets to avoid downtime"
    )
    prep_parser.add_argument(
        "--start", type=int, default=1, help="Starting VNet number (default: 1)"
    )
    prep_parser.add_argument(
        "--end", type=int, default=100, help="Ending VNet number (default: 100)"
    )
    prep_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without making changes",
    )
    prep_parser.add_argument(
        "--no-reload", action="store_true", help="Skip SDN reload at the end"
    )

    # Reload SDN
    reload_parser = net_subparsers.add_parser("reload", help="Reload SDN configuration")


def setup_range_commands(subparsers):
    """Set up high-level range management commands."""
    range_parser = subparsers.add_parser(
        "range", help="High-level range setup operations"
    )
    range_subparsers = range_parser.add_subparsers(
        dest="range_command", help="Range commands"
    )

    # Setup range for user
    setup_parser = range_subparsers.add_parser(
        "setup", help="Set up complete range for user"
    )
    setup_parser.add_argument("username", help="Username (without realm)")
    setup_parser.add_argument(
        "--base-vmid",
        type=int,
        default=150,
        help="Gateway VM to clone from (default: 150)",
    )
    setup_parser.add_argument(
        "--vmids",
        type=str,
        help="Comma-separated list of additional VMIDs to clone (e.g., '100,102,103')",
    )
    setup_parser.add_argument(
        "--pool-suffix", default="-range", help="Pool name suffix (default: -range)"
    )

    # Setup ranges for all AD users
    setup_all_parser = range_subparsers.add_parser(
        "setup-all", help="Set up ranges for all AD users"
    )
    setup_all_parser.add_argument(
        "--base-vmid",
        type=int,
        default=150,
        help="Gateway VM to clone from (default: 150)",
    )
    setup_all_parser.add_argument(
        "--vmids",
        type=str,
        help="Comma-separated list of additional VMIDs to clone for each user (e.g., '100,102,103')",
    )
    setup_all_parser.add_argument(
        "--pool-suffix", default="-range", help="Pool name suffix (default: -range)"
    )
    setup_all_parser.add_argument(
        "--skip-admins", action="store_true", help="Skip users with -adm in name"
    )


def handle_vm_commands(args, manager: RangeManager):
    """Handle VM management commands."""
    if args.vm_command == "list":
        vms = manager.vms.get_vms()
        if args.pattern:
            vms = manager.vms.find_vms_by_pattern(args.pattern)

        print(f"{'VMID':<6} {'Name':<30} {'Status':<10} {'Node':<10}")
        print("-" * 60)
        for vm in vms:
            print(
                f"{vm['vmid']:<6} {vm.get('name', 'Unknown'):<30} {vm.get('status', 'Unknown'):<10} {vm.get('node', 'Unknown'):<10}"
            )

    elif args.vm_command == "power":
        count = manager.vms.set_power_by_pattern(args.pattern, args.action)
        print(f"Affected {count} VMs with action '{args.action}'")

    elif args.vm_command == "nuke":
        if args.dry_run:
            vms = manager.vms.find_vms_by_pattern(args.pattern)
            print(f"Would delete {len(vms)} VMs:")
            for vm in vms:
                print(f"  - {vm['vmid']} ({vm.get('name', 'Unknown')})")
        else:
            count = manager.vms.nuke_by_pattern(args.pattern, not args.no_stop)
            print(f"Deleted {count} VMs")

    elif args.vm_command == "nuke-gw":
        if args.dry_run:
            vms = manager.vms.find_vms_by_suffix("-range-gw")
            print(f"Would delete {len(vms)} gateway VMs:")
            for vm in vms:
                print(f"  - {vm['vmid']} ({vm.get('name', 'Unknown')})")
        else:
            count = manager.vms.nuke_gateway_vms()
            print(f"Deleted {count} gateway VMs")

    elif args.vm_command == "clone":
        new_vmid = manager.proxmox.cluster.nextid.get()
        success = manager.vms.clone_vm(
            args.base_vmid, new_vmid, args.name, args.pool, args.full
        )
        if success:
            print(
                f"Successfully cloned VM {args.base_vmid} to {new_vmid} ({args.name})"
            )
        else:
            print("Failed to clone VM")


def handle_user_commands(args, manager: RangeManager):
    """Handle user management commands."""
    if args.user_command == "list":
        users = manager.users.get_users(args.realm)
        print(f"{'User ID':<30} {'Enabled':<8} {'Groups'}")
        print("-" * 50)
        for user in users:
            print(
                f"{user.get('userid', 'Unknown'):<30} {user.get('enable', 1):<8} {user.get('groups', '')}"
            )

    elif args.user_command == "delete":
        success = manager.users.delete_user(args.userid)
        if success:
            print(f"Successfully deleted user {args.userid}")
        else:
            print("Failed to delete user (may not exist)")

    elif args.user_command == "purge-pve":
        count = manager.users.purge_pve_users(args.dry_run)
        if args.dry_run:
            print(f"Would delete {count} @pve users")
        else:
            print(f"Processed {count} @pve users")

    elif args.user_command == "validate":
        if manager.users.validate_ad_user(args.username):
            print(f"User {args.username}@ad exists")
        else:
            print(manager.users.get_ad_user_error_message(args.username))


def handle_network_commands(args, manager: RangeManager):
    """Handle network management commands."""
    if args.net_command == "list":
        vnets = manager.networks.get_vnets()
        print(f"{'VNet Name':<15} {'Zone':<15} {'Alias':<20}")
        print("-" * 50)
        for vnet in vnets:
            print(
                f"{vnet.get('vnet', 'Unknown'):<15} {vnet.get('zone', 'Unknown'):<15} {vnet.get('alias', ''):<20}"
            )

    elif args.net_command == "create":
        success = manager.networks.create_vnet(args.name, args.zone, args.alias)
        if success:
            print(f"Successfully created VNet {args.name}")
        else:
            print("Failed to create VNet")

    elif args.net_command == "delete":
        success = manager.networks.delete_vnet(args.name)
        if success:
            print(f"Successfully deleted VNet {args.name}")
        else:
            print("Failed to delete VNet")

    elif args.net_command == "ensure-user":
        # Validate user exists in AD realm
        if not manager.users.validate_ad_user(args.username):
            print(manager.users.get_ad_user_error_message(args.username))
            return

        vnet_name = manager.networks.ensure_user_vnet(args.username, args.zone)
        if vnet_name:
            print(f"VNet {vnet_name} ensured for user {args.username}@ad")
        else:
            print(f"Failed to ensure VNet for user {args.username}@ad")

    elif args.net_command == "ensure-all":
        # Sync AD realm first
        try:
            manager.proxmox.access.domains("ad").sync.post()
            print("Synced AD realm")
        except Exception as e:
            print(f"Warning: AD realm sync failed: {e}")

        # Get all AD users
        ad_users = manager.users.get_users("ad")
        created_count = 0

        for user in ad_users:
            userid = user.get("userid")
            if not userid or "-adm" in userid:
                continue

            username = userid.split("@")[0]
            vnet_name = manager.networks.ensure_user_vnet(username, args.zone)
            if vnet_name:
                print(f"Ensured VNet {vnet_name} for {username}")
                created_count += 1
            else:
                print(f"Failed to ensure VNet for {username}")

        # Reload SDN
        if manager.networks.reload_sdn():
            print("Reloaded SDN configuration")

        print(f"Ensured VNets for {created_count} users")

    elif args.net_command == "pre-prep":
        # Load infrastructure configuration for VNet naming
        infra_config = load_infra_config()
        naming_config = infra_config.get("naming", {})
        vnet_prefix = naming_config.get("vnet_prefix", "RN")
        zone = naming_config.get("vnet_zone", "CMPCCDC")

        # Get existing VNets to avoid duplicates
        existing_vnets = manager.networks.get_vnets()
        existing_vnet_names = {vnet.get("vnet", "") for vnet in existing_vnets}

        created_count = 0
        skipped_count = 0

        print(
            f"{'DRY RUN: ' if args.dry_run else ''}Creating VNets {vnet_prefix}{args.start} to {vnet_prefix}{args.end} in zone {zone}"
        )

        for i in range(args.start, args.end + 1):
            vnet_name = f"{vnet_prefix}{i}"

            if vnet_name in existing_vnet_names:
                print(f"VNet {vnet_name} already exists, skipping")
                skipped_count += 1
                continue

            if args.dry_run:
                print(f"DRY RUN: Would create VNet {vnet_name} in zone {zone}")
                created_count += 1
            else:
                # Create VNet with no alias (empty string means unassigned)
                if manager.networks.create_vnet(vnet_name, zone, alias=None):
                    print(f"Created VNet {vnet_name}")
                    created_count += 1
                else:
                    print(f"Failed to create VNet {vnet_name}")

        print(f"Summary: {created_count} VNets created, {skipped_count} skipped")

        # Reload SDN configuration unless disabled or dry run
        if not args.no_reload and not args.dry_run and created_count > 0:
            print("Reloading SDN configuration...")
            if manager.networks.reload_sdn():
                print("SDN configuration reloaded successfully")
            else:
                print("Failed to reload SDN configuration")
        elif args.dry_run:
            print("DRY RUN: Would reload SDN configuration")
        elif created_count == 0:
            print("No VNets created, skipping SDN reload")

    elif args.net_command == "reload":
        success = manager.networks.reload_sdn()
        if success:
            print("Successfully reloaded SDN configuration")
        else:
            print("Failed to reload SDN configuration")


def handle_range_commands(args, manager: RangeManager):
    """Handle high-level range management commands."""
    if args.range_command == "setup":
        # First, set up the gateway VM and infrastructure
        success = manager.setup_user_range(
            args.username, args.base_vmid, args.pool_suffix
        )

        if not success:
            print(f"Failed to set up gateway for {args.username}")
            return

        # Clone additional VMs if specified
        if args.vmids:
            try:
                additional_vmids = [int(vmid.strip()) for vmid in args.vmids.split(",")]
                print(f"Cloning additional VMs: {additional_vmids}")
            except ValueError as e:
                print(f"Error parsing VMIDs: {e}")
                return

            pool_name = f"{args.username}{args.pool_suffix}"
            all_vms_success = True

            for base_vmid in additional_vmids:
                new_vmid = manager.proxmox.cluster.nextid.get()
                clone_name = f"{args.username}-range-{base_vmid}"

                print(f"  Cloning VM {base_vmid} to {new_vmid} ({clone_name})...")
                vm_success = manager.vms.clone_vm(
                    base_vmid, new_vmid, clone_name, pool_name
                )

                if vm_success:
                    # Set permissions for the user on this VM
                    try:
                        manager.proxmox.access.acl.put(
                            path=f"/vms/{new_vmid}",
                            users=f"{args.username}@ad",
                            roles="Administrator",
                        )
                        print(f"  ✓ Created VM {new_vmid} for {args.username}@ad")
                    except Exception as e:
                        print(f"  ✗ Failed to set permissions on VM {new_vmid}: {e}")
                        all_vms_success = False
                else:
                    print(f"  ✗ Failed to clone VM {base_vmid}")
                    all_vms_success = False

            if all_vms_success:
                print(f"Successfully set up complete range for {args.username}")
            else:
                print(f"Partially set up range for {args.username}")
        else:
            print(f"Successfully set up range for {args.username}")

    elif args.range_command == "setup-all":
        # Sync AD realm first
        try:
            manager.proxmox.access.domains("ad").sync.post()
            print("Synced AD realm")
        except Exception as e:
            print(f"Warning: AD realm sync failed: {e}")

        # Parse additional VMIDs if provided
        additional_vmids = []
        if args.vmids:
            try:
                additional_vmids = [int(vmid.strip()) for vmid in args.vmids.split(",")]
                print(f"Will clone additional VMs: {additional_vmids}")
            except ValueError as e:
                print(f"Error parsing VMIDs: {e}")
                return

        # Get all AD users
        ad_users = manager.users.get_users("ad")
        setup_count = 0

        for user in ad_users:
            userid = user.get("userid")
            if not userid:
                continue

            if args.skip_admins and "-adm" in userid:
                print(f"Skipping admin user {userid}")
                continue

            username = userid.split("@")[0]
            print(f"Setting up range for {username}...")

            # First, set up the gateway VM and infrastructure
            success = manager.setup_user_range(
                username, args.base_vmid, args.pool_suffix
            )

            if not success:
                print(f"✗ Failed to set up gateway for {username}")
                continue

            # Clone additional VMs if specified
            pool_name = f"{username}{args.pool_suffix}"
            all_vms_success = True

            for base_vmid in additional_vmids:
                new_vmid = manager.proxmox.cluster.nextid.get()
                clone_name = f"{username}-range-{base_vmid}"

                print(f"  Cloning VM {base_vmid} to {new_vmid} ({clone_name})...")
                vm_success = manager.vms.clone_vm(
                    base_vmid, new_vmid, clone_name, pool_name
                )

                if vm_success:
                    # Set permissions for the user on this VM
                    try:
                        manager.proxmox.access.acl.put(
                            path=f"/vms/{new_vmid}",
                            users=f"{username}@ad",
                            roles="Administrator",
                        )
                        print(f"  ✓ Created VM {new_vmid} for {username}@ad")
                    except Exception as e:
                        print(f"  ✗ Failed to set permissions on VM {new_vmid}: {e}")
                        all_vms_success = False
                else:
                    print(f"  ✗ Failed to clone VM {base_vmid}")
                    all_vms_success = False

            if all_vms_success:
                print(f"✓ Successfully set up complete range for {username}")
                setup_count += 1
            else:
                print(f"⚠ Partially set up range for {username}")
                setup_count += 1

        print(f"Set up ranges for {setup_count} users")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Proxmox Range Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s vm list --pattern ".*range.*"
  %(prog)s vm power start ".*windows.*"
  %(prog)s vm nuke ".*test.*" --dry-run
  %(prog)s user validate john.doe
  %(prog)s user list --realm ad
  %(prog)s network ensure-all
  %(prog)s range setup john.doe --base-vmid 150
        """,
    )

    parser.add_argument("--config", help="Path to secrets.toml config file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Set up command parsers
    setup_vm_commands(subparsers)
    setup_user_commands(subparsers)
    setup_network_commands(subparsers)
    setup_range_commands(subparsers)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("rangemgr").setLevel(logging.DEBUG)

    try:
        # Load configuration and create manager
        secrets = load_secrets(args.config)
        manager = RangeManager(secrets)

        # Route to appropriate handler
        if args.command == "vm":
            handle_vm_commands(args, manager)
        elif args.command == "user":
            handle_user_commands(args, manager)
        elif args.command == "network":
            handle_network_commands(args, manager)
        elif args.command == "range":
            handle_range_commands(args, manager)

        return 0

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
