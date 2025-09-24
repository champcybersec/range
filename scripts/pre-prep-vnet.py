#!/usr/bin/env python3
"""
Pre-create VNets to avoid downtime during user range setup.

This script creates VNets using the naming scheme from infra.toml, pre-defining
VNets 1-100 (or a configurable range) so that when new users are created,
there's no need to reload SDN config while Proxmox is in use by end users.

The script will:
1. Load configuration from infra.toml and secrets.toml
2. Create VNets RN1-RN100 (configurable) with no username in alias field
3. Perform SDN reload at the end using raw requests API
"""

import os
import sys
import argparse
from typing import Dict, Any, Optional

# Add parent directory to path so we can import rangemgr
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rangemgr import RangeManager, load_secrets, load_infra_config, logger


def create_vnet_range(
    manager: RangeManager, start: int = 1, end: int = 100, dry_run: bool = False
) -> tuple[int, int]:
    """
    Create a range of VNets with no alias assigned.

    Args:
        manager: RangeManager instance
        start: Starting VNet number (inclusive)
        end: Ending VNet number (inclusive)
        dry_run: If True, only show what would be created

    Returns:
        Tuple of (created_count, skipped_count)
    """
    # Load infrastructure configuration
    infra_config = load_infra_config()
    naming_config = infra_config.get("naming", {})
    vnet_prefix = naming_config.get("vnet_prefix", "RN")
    zone = naming_config.get("vnet_zone", "CMPCCDC")

    # Get existing VNets to avoid duplicates
    existing_vnets = manager.networks.get_vnets()
    existing_vnet_names = {vnet.get("vnet", "") for vnet in existing_vnets}

    created_count = 0
    skipped_count = 0

    logger.info(f"{'DRY RUN: ' if dry_run else ''}Creating VNets {vnet_prefix}{start} to {vnet_prefix}{end} in zone {zone}")

    for i in range(start, end + 1):
        vnet_name = f"{vnet_prefix}{i}"

        if vnet_name in existing_vnet_names:
            logger.info(f"VNet {vnet_name} already exists, skipping")
            skipped_count += 1
            continue

        if dry_run:
            logger.info(f"DRY RUN: Would create VNet {vnet_name} in zone {zone}")
            created_count += 1
        else:
            # Create VNet with no alias (empty string means unassigned)
            if manager.networks.create_vnet(vnet_name, zone, alias=None):
                logger.info(f"Created VNet {vnet_name}")
                created_count += 1
            else:
                logger.error(f"Failed to create VNet {vnet_name}")

    return created_count, skipped_count


def main():
    """Main function for the pre-prep-vnet script."""
    parser = argparse.ArgumentParser(
        description="Pre-create VNets to avoid downtime during user setup"
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting VNet number (default: 1)"
    )
    parser.add_argument(
        "--end",
        type=int,
        default=100,
        help="Ending VNet number (default: 100)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without making changes"
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Skip SDN reload at the end"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set up logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    try:
        # Load configuration and create manager
        logger.info("Loading configuration...")
        secrets = load_secrets()
        manager = RangeManager(secrets)

        # Create VNet range
        created_count, skipped_count = create_vnet_range(
            manager, args.start, args.end, args.dry_run
        )

        logger.info(f"Summary: {created_count} VNets created, {skipped_count} skipped")

        # Reload SDN configuration unless disabled or dry run
        if not args.no_reload and not args.dry_run and created_count > 0:
            logger.info("Reloading SDN configuration...")
            if manager.networks.reload_sdn():
                logger.info("SDN configuration reloaded successfully")
            else:
                logger.error("Failed to reload SDN configuration")
                return 1
        elif args.dry_run:
            logger.info("DRY RUN: Would reload SDN configuration")
        elif created_count == 0:
            logger.info("No VNets created, skipping SDN reload")

        logger.info("Pre-prep VNet script completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Error in pre-prep VNet script: {e}")
        return 1


if __name__ == "__main__":
    import logging
    sys.exit(main())