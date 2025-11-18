"""
Unit tests for username matching in NetworkManager.

This module tests the fix for the username matching issue where
VNet alias comparisons were case-sensitive and didn't handle whitespace.
"""

import unittest
from unittest.mock import Mock, MagicMock
from rangemgr import NetworkManager


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
        self.assertEqual(result, "RN3", "Should match NiLuFeR.GuNgOr (case insensitive)")

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


if __name__ == "__main__":
    unittest.main()
