"""
Unit tests for username matching in NetworkManager.

This module tests the fix for the username matching issue where
VNet alias comparisons were case-sensitive and didn't handle whitespace.
"""

import unittest
from unittest.mock import Mock, MagicMock, call, patch
from rangemgr import NetworkManager, PoolManager


class TestUsernameMatching(unittest.TestCase):
    """Test cases for VNet username matching."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock ProxmoxAPI client
        self.mock_proxmox = MagicMock()
        self.mock_secrets = {
            "proxmox": {
                "host": "test.example.com",
                "user": "root@pam",
                "password": "test",
                "verify_ssl": False,
                "node": "pve",
            }
        }
        self.network_manager = NetworkManager(self.mock_proxmox, self.mock_secrets)

    def test_exact_match_lowercase(self):
        """Test exact match with lowercase username."""
        # Mock VNets data
        mock_vnets = [
            {"vnet": "RN1", "alias": "samuel.mclamb"},
            {"vnet": "RN2", "alias": "sam.royal"},
            {"vnet": "RN3", "alias": "nilufer.gungor"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test exact match
        result = self.network_manager.get_vnet_for_user("samuel.mclamb")
        self.assertEqual(result, "RN1")

        result = self.network_manager.get_vnet_for_user("sam.royal")
        self.assertEqual(result, "RN2")

        result = self.network_manager.get_vnet_for_user("nilufer.gungor")
        self.assertEqual(result, "RN3")

    def test_case_insensitive_match(self):
        """Test case-insensitive matching."""
        # Mock VNets with different case in alias
        mock_vnets = [
            {"vnet": "RN1", "alias": "SAMUEL.MCLAMB"},
            {"vnet": "RN2", "alias": "Sam.Royal"},
            {"vnet": "RN3", "alias": "NiLuFeR.GuNgOr"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test case-insensitive match
        result = self.network_manager.get_vnet_for_user("samuel.mclamb")
        self.assertEqual(result, "RN1", "Should match SAMUEL.MCLAMB (case insensitive)")

        result = self.network_manager.get_vnet_for_user("sam.royal")
        self.assertEqual(result, "RN2", "Should match Sam.Royal (case insensitive)")

        result = self.network_manager.get_vnet_for_user("nilufer.gungor")
        self.assertEqual(
            result, "RN3", "Should match NiLuFeR.GuNgOr (case insensitive)"
        )

    def test_whitespace_handling(self):
        """Test whitespace handling in aliases and usernames."""
        # Mock VNets with whitespace in alias
        mock_vnets = [
            {"vnet": "RN1", "alias": " samuel.mclamb "},
            {"vnet": "RN2", "alias": "sam.royal\t"},
            {"vnet": "RN3", "alias": "\nnilufer.gungor"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test whitespace handling
        result = self.network_manager.get_vnet_for_user("samuel.mclamb")
        self.assertEqual(
            result, "RN1", "Should match ' samuel.mclamb ' (strip whitespace)"
        )

        result = self.network_manager.get_vnet_for_user("sam.royal")
        self.assertEqual(
            result, "RN2", "Should match 'sam.royal\\t' (strip whitespace)"
        )

        result = self.network_manager.get_vnet_for_user("nilufer.gungor")
        self.assertEqual(
            result, "RN3", "Should match '\\nnilufer.gungor' (strip whitespace)"
        )

    def test_no_partial_match(self):
        """Test that partial matches are NOT matched."""
        # Mock VNets with similar names
        mock_vnets = [
            {"vnet": "RN1", "alias": "samuel.mclamb"},
            {"vnet": "RN2", "alias": "sam.royal"},
            {"vnet": "RN3", "alias": "sam"},  # Partial name
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test that "sam" does NOT match "samuel.mclamb" or "sam.royal"
        result = self.network_manager.get_vnet_for_user("samuel.mclamb")
        self.assertEqual(result, "RN1", "Should match exact username samuel.mclamb")

        result = self.network_manager.get_vnet_for_user("sam.royal")
        self.assertEqual(result, "RN2", "Should match exact username sam.royal")

        result = self.network_manager.get_vnet_for_user("sam")
        self.assertEqual(result, "RN3", "Should match exact username sam")

    def test_no_match_returns_none(self):
        """Test that no match returns None."""
        # Mock VNets
        mock_vnets = [
            {"vnet": "RN1", "alias": "samuel.mclamb"},
            {"vnet": "RN2", "alias": "sam.royal"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test no match
        result = self.network_manager.get_vnet_for_user("nonexistent.user")
        self.assertIsNone(result, "Should return None for non-existent user")

    def test_empty_alias(self):
        """Test handling of empty or missing aliases."""
        # Mock VNets with empty/missing aliases
        mock_vnets = [
            {"vnet": "RN1", "alias": ""},
            {"vnet": "RN2"},  # No alias field
            {"vnet": "RN3", "alias": "   "},  # Whitespace only
            {"vnet": "RN4", "alias": "valid.user"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test that empty aliases don't match empty username
        result = self.network_manager.get_vnet_for_user("")
        self.assertIsNone(result, "Empty username should not match empty aliases")

        # Test that valid user still matches
        result = self.network_manager.get_vnet_for_user("valid.user")
        self.assertEqual(result, "RN4", "Should match valid user")

    def test_username_with_whitespace(self):
        """Test username input with leading/trailing whitespace."""
        # Mock VNets
        mock_vnets = [
            {"vnet": "RN1", "alias": "samuel.mclamb"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test username with whitespace
        result = self.network_manager.get_vnet_for_user("  samuel.mclamb  ")
        self.assertEqual(
            result, "RN1", "Should match after stripping whitespace from username"
        )

    def test_club_specific_match(self):
        """Ensure club-prefixed aliases are matched when club is provided."""
        mock_vnets = [
            {"vnet": "RN1", "alias": "CCDC/samuel.mclamb"},
            {"vnet": "RN2", "alias": "samuel.mclamb"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        result = self.network_manager.get_vnet_for_user("samuel.mclamb", club="CCDC")
        self.assertEqual(result, "RN1", "Should match the club-specific alias first")

    def test_club_fallback_to_legacy_alias(self):
        """Fall back to legacy alias when older hyphenated entry exists."""
        mock_vnets = [
            {"vnet": "RN2", "alias": "CCDC-samuel.mclamb"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        result = self.network_manager.get_vnet_for_user("samuel.mclamb", club="CCDC")
        self.assertEqual(
            result,
            "RN2",
            "Should fall back to legacy alias when club-specific alias absent",
        )


class TestEnsureUserVnet(unittest.TestCase):
    """Test cases for ensure_user_vnet username matching."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock ProxmoxAPI client
        self.mock_proxmox = MagicMock()
        self.mock_secrets = {
            "proxmox": {
                "host": "test.example.com",
                "user": "root@pam",
                "password": "test",
                "verify_ssl": False,
                "node": "pve",
            }
        }
        self.network_manager = NetworkManager(self.mock_proxmox, self.mock_secrets)

    def test_existing_vnet_case_insensitive(self):
        """Test that ensure_user_vnet finds existing VNet case-insensitively."""
        # Mock VNets with different case
        mock_vnets = [
            {"vnet": "RN1", "alias": "SAMUEL.MCLAMB"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test that it finds the existing VNet
        result = self.network_manager.ensure_user_vnet("samuel.mclamb", "CMPCCDC")
        self.assertEqual(
            result,
            "RN1",
            "Should find existing VNet with case-insensitive alias match",
        )

    def test_existing_vnet_with_whitespace(self):
        """Test that ensure_user_vnet finds existing VNet with whitespace."""
        # Mock VNets with whitespace in alias
        mock_vnets = [
            {"vnet": "RN1", "alias": " samuel.mclamb "},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        # Test that it finds the existing VNet
        result = self.network_manager.ensure_user_vnet("samuel.mclamb", "CMPCCDC")
        self.assertEqual(
            result, "RN1", "Should find existing VNet after stripping whitespace"
        )

    def test_create_vnet_with_club_alias(self):
        """Ensure newly created VNets use the club-prefixed alias."""
        self.network_manager.get_vnets = Mock(return_value=[])
        self.network_manager.create_vnet = Mock(return_value=True)

        result = self.network_manager.ensure_user_vnet(
            "samuel.mclamb", "CMPCCDC", club="CCDC"
        )

        self.assertEqual(result, "RN37", "Should allocate the next RN starting at 37")
        self.network_manager.create_vnet.assert_called_with(
            "RN37", "CMPCCDC", "CCDC/samuel.mclamb"
        )

    def test_existing_legacy_hyphen_alias(self):
        """Legacy hyphenated aliases should satisfy ensure requests."""
        mock_vnets = [
            {"vnet": "RN5", "alias": "CCDC-samuel.mclamb"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        result = self.network_manager.ensure_user_vnet(
            "samuel.mclamb", "CMPCCDC", club="CCDC"
        )
        self.assertEqual(
            result,
            "RN5",
            "Legacy hyphenated alias should be treated as existing assignment",
        )


class TestClearAllVnetAliases(unittest.TestCase):
    """Tests for clearing VNet aliases."""

    def setUp(self):
        self.mock_proxmox = MagicMock()
        self.mock_secrets = {
            "proxmox": {
                "host": "test.example.com",
                "user": "root@pam",
                "password": "test",
                "verify_ssl": False,
                "node": "pve",
            }
        }
        self.network_manager = NetworkManager(self.mock_proxmox, self.mock_secrets)

    def test_skips_non_rn_vnets(self):
        """Ensure aliases are only cleared for RN-prefixed VNets."""
        mock_vnets = [
            {"vnet": "RN1", "zone": "CMPCCDC", "alias": "user.one"},
            {"vnet": "MG1", "zone": "CMPCCDC", "alias": "user.two"},
            {"vnet": "RN2", "zone": "CMPCCDC", "alias": "user.three"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        cleared, failed = self.network_manager.clear_all_vnet_aliases()

        self.assertEqual(cleared, 2)
        self.assertEqual(failed, [])
        called_vnets = [
            args[0] for args, _ in self.mock_proxmox.cluster.sdn.vnets.call_args_list
        ]
        self.assertEqual(set(called_vnets), {"RN1", "RN2"})
        self.assertEqual(self.mock_proxmox.cluster.sdn.vnets.call_count, 2)
        self.mock_proxmox.cluster.sdn.vnets.return_value.put.assert_has_calls(
            [
                call(zone="CMPCCDC", alias=""),
                call(zone="CMPCCDC", alias=""),
            ],
            any_order=False,
        )

    def test_dry_run_does_not_apply_changes(self):
        """Dry run should report affected VNets without API calls."""
        mock_vnets = [
            {"vnet": "RN10", "zone": "CMPCCDC", "alias": "user.four"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        cleared, failed = self.network_manager.clear_all_vnet_aliases(dry_run=True)

        self.assertEqual(cleared, 1)
        self.assertEqual(failed, [])
        self.mock_proxmox.cluster.sdn.vnets.assert_not_called()

    def test_exclude_patterns_prevent_clearing_aliases(self):
        """Exclude patterns should skip matching VNets."""
        mock_vnets = [
            {"vnet": "RN1", "zone": "CMPCCDC", "alias": "Keep.Me"},
            {"vnet": "RN2", "zone": "CMPCCDC", "alias": "Clear.Me"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        cleared, failed = self.network_manager.clear_all_vnet_aliases(exclude=["keep"])

        self.assertEqual(cleared, 1)
        self.assertEqual(failed, [])
        self.mock_proxmox.cluster.sdn.vnets.assert_called_once_with("RN2")
        self.mock_proxmox.cluster.sdn.vnets.return_value.put.assert_called_once_with(
            zone="CMPCCDC", alias=""
        )

    def test_exclude_patterns_match_description(self):
        """Exclude patterns should consider VNet descriptions."""
        mock_vnets = [
            {
                "vnet": "RN3",
                "zone": "CMPCCDC",
                "alias": "Clear.Me",
                "description": "Keep Label",
            },
            {"vnet": "RN4", "zone": "CMPCCDC", "alias": "Clear.Also"},
        ]
        self.network_manager.get_vnets = Mock(return_value=mock_vnets)

        cleared, failed = self.network_manager.clear_all_vnet_aliases(exclude=["keep"])

        self.assertEqual(cleared, 1)
        self.assertEqual(failed, [])
        called_vnets = [
            args[0] for args, _ in self.mock_proxmox.cluster.sdn.vnets.call_args_list
        ]
        self.assertEqual(called_vnets, ["RN4"])


class TestPoolManager(unittest.TestCase):
    """Test cases for pool matching and deletion safeguards."""

    def setUp(self):
        self.mock_proxmox = MagicMock()
        self.mock_proxmox.pools.delete.return_value = {"data": None}
        self.mock_proxmox.pools.get.return_value = {"members": []}
        self.pool_manager = PoolManager(self.mock_proxmox)

    def test_find_pools_by_pattern_excludes_protected(self):
        """Ensure protected pools are excluded from match results."""
        matches = self.pool_manager.find_pools_by_pattern(r".*-range$")
        self.assertEqual(matches, ["john.doe-range", "jane.doe-range"])

    def test_nuke_pools_by_pattern_deletes_matches(self):
        """nuke_pools_by_pattern should delete matched, non-protected pools."""
        self.pool_manager.delete_pool = Mock(return_value=True)

        matches, deleted = self.pool_manager.nuke_pools_by_pattern(r".*-range$")

        self.assertEqual(matches, ["john.doe-range", "jane.doe-range"])
        self.assertEqual(deleted, ["john.doe-range", "jane.doe-range"])
        self.pool_manager.delete_pool.assert_has_calls(
            [call("john.doe-range"), call("jane.doe-range")], any_order=False
        )

    def test_delete_pool_handles_slash_names(self):
        """Pool deletions should support slash-separated pool IDs."""
        pool_name = "WICYS/wicys9-range"

        result = self.pool_manager.delete_pool(pool_name)

        self.assertTrue(result)
        self.mock_proxmox.pools.delete.assert_called_once_with(poolid=pool_name)

    def test_delete_pool_removes_members_with_vm_manager(self):
        """Pool deletion should remove member VMs before deleting the pool."""
        self.mock_proxmox.pools.get.return_value = {
            "members": [
                {"type": "qemu", "vmid": 101},
                {"type": "storage", "id": "local-lvm"},
            ]
        }
        mock_vm_manager = MagicMock()
        mock_vm_manager.stop_vm.return_value = True
        mock_vm_manager.delete_vm.return_value = True
        mock_vm_manager.get_vm_status.return_value = "running"

        pool_manager = PoolManager(self.mock_proxmox, vm_manager=mock_vm_manager)

        result = pool_manager.delete_pool("john.doe-range")

        self.assertTrue(result)
        mock_vm_manager.get_vm_status.assert_called_with(101)
        mock_vm_manager.stop_vm.assert_called_with(101, force=True)
        mock_vm_manager.delete_vm.assert_called_with(101, force=True)
        self.mock_proxmox.pools.delete.assert_called_with(poolid="john.doe-range")

    def test_delete_pool_member_lookup_handles_list_response(self):
        """Pool member discovery should handle list responses from the API."""
        self.mock_proxmox.pools.get.return_value = [
            {"poolid": "other", "members": [{"type": "qemu", "vmid": 50}]},
            {
                "poolid": "john.doe-range",
                "members": [
                    {"type": "qemu", "vmid": 101},
                ],
            },
        ]
        mock_vm_manager = MagicMock()
        mock_vm_manager.stop_vm.return_value = True
        mock_vm_manager.delete_vm.return_value = True
        mock_vm_manager.get_vm_status.return_value = "running"

        pool_manager = PoolManager(self.mock_proxmox, vm_manager=mock_vm_manager)

        result = pool_manager.delete_pool("john.doe-range")

        self.assertTrue(result)
        mock_vm_manager.get_vm_status.assert_called_with(101)
        mock_vm_manager.stop_vm.assert_called_with(101, force=True)
        mock_vm_manager.delete_vm.assert_called_with(101, force=True)
        self.mock_proxmox.pools.delete.assert_called_with(poolid="john.doe-range")

    def test_delete_pool_skips_stop_when_already_off(self):
        """VM stop should be skipped when status indicates the VM is already off."""
        self.mock_proxmox.pools.get.return_value = {
            "members": [{"type": "qemu", "vmid": 202}]
        }
        mock_vm_manager = MagicMock()
        mock_vm_manager.get_vm_status.return_value = "stopped"
        mock_vm_manager.delete_vm.return_value = True

        pool_manager = PoolManager(self.mock_proxmox, vm_manager=mock_vm_manager)

        result = pool_manager.delete_pool("club/user-range")

        self.assertTrue(result)
        mock_vm_manager.stop_vm.assert_not_called()
        mock_vm_manager.delete_vm.assert_called_with(202, force=True)

    @patch("rangemgr.requests.delete")
    @patch("rangemgr.requests.post")
    def test_delete_pool_fallback_to_raw_http(self, mock_post, mock_delete):
        """Fallback raw HTTP deletion should run when proxmoxer delete fails."""
        secrets = {
            "proxmox": {
                "host": "https://pve.example.com",
                "user": "root@pam",
                "password": "secret",
                "verify_ssl": False,
            }
        }
        pool_manager = PoolManager(self.mock_proxmox, secrets)

        # Simulate proxmoxer failure
        self.mock_proxmox.pools.delete.side_effect = Exception("501 Not Implemented")

        # Mock auth ticket response
        mock_auth_response = Mock()
        mock_auth_response.json.return_value = {
            "data": {
                "ticket": "ticket",
                "CSRFPreventionToken": "token",
            }
        }
        mock_auth_response.raise_for_status = Mock()
        mock_post.return_value = mock_auth_response

        # Mock delete response
        mock_delete_response = Mock()
        mock_delete_response.raise_for_status = Mock()
        mock_delete.return_value = mock_delete_response

        result = pool_manager.delete_pool("CLUB/user-range")

        self.assertTrue(result)
        mock_post.assert_called_with(
            "https://pve.example.com:8006/api2/json/access/ticket",
            data={"username": "root@pam", "password": "secret"},
            verify=False,
            timeout=30,
        )
        mock_delete.assert_called_once()
        delete_url = mock_delete.call_args[0][0]
        delete_kwargs = mock_delete.call_args.kwargs
        self.assertEqual(
            delete_url, "https://pve.example.com:8006/api2/json/pools"
        )
        self.assertIn("params", delete_kwargs)
        self.assertEqual(delete_kwargs["params"], {"poolid": "CLUB/user-range"})

    def test_nuke_pools_by_pattern_dry_run(self):
        """Dry run should not delete any pools."""
        matches, deleted = self.pool_manager.nuke_pools_by_pattern(
            r".*-range$", dry_run=True
        )

        self.assertEqual(matches, ["john.doe-range", "jane.doe-range"])
        self.assertEqual(deleted, [])


if __name__ == "__main__":
    unittest.main()
