"""
Unit tests for username matching in NetworkManager.

This module tests the fix for the username matching issue where
VNet alias comparisons were case-sensitive and didn't handle whitespace.
"""

import unittest
from unittest.mock import Mock, MagicMock, call
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


class TestPoolManager(unittest.TestCase):
    """Test cases for pool matching and deletion safeguards."""

    def setUp(self):
        self.mock_proxmox = MagicMock()
        self.pool_manager = PoolManager(self.mock_proxmox)
        self.mock_proxmox.pools.get.return_value = [
            {"poolid": "john.doe-range"},
            {"poolid": "prod"},
            {"poolid": "infra-range"},
            {"poolid": "jane.doe-range"},
        ]

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

    def test_nuke_pools_by_pattern_dry_run(self):
        """Dry run should not delete any pools."""
        matches, deleted = self.pool_manager.nuke_pools_by_pattern(
            r".*-range$", dry_run=True
        )

        self.assertEqual(matches, ["john.doe-range", "jane.doe-range"])
        self.assertEqual(deleted, [])


if __name__ == "__main__":
    unittest.main()
