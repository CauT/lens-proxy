"""LAN configuration semantics; network behavior lives in test_lan_proxy.py."""
import unittest
from network import LANAccess


class LANPolicy(unittest.TestCase):
    def test_disabled_and_explicit_private_host_without_client_registration(self):
        self.assertIsNone(LANAccess.parse(None))
        policy = LANAccess.parse("192.168.2.250")
        self.assertEqual(policy.address, "192.168.2.250")

    def test_ambiguous_or_nonlocal_bind_address_is_rejected(self):
        for host in ("0.0.0.0", "127.0.0.1", "::", "8.8.8.8", "*", "192.168.2.0/24", "240.0.0.1"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                LANAccess.parse(host)


if __name__ == "__main__":
    unittest.main(verbosity=2)
