"""Guard trusted operator AF_NETLINK needed to bootstrap the isolated WAL child.

These source-level contracts do not substitute for target-host kernel tests.
Untrusted coding agents still require a separate proven network boundary.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FAMILIES = "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"


class OperatorNetlinkContractTests(unittest.TestCase):
    def test_persistent_operator_allows_netlink_route_for_bwrap_setup(self) -> None:
        unit = (ROOT / "systemd/grabowski-operator.service.example").read_text(
            encoding="utf-8"
        )
        families = [
            line.strip() for line in unit.splitlines()
            if line.strip().startswith("RestrictAddressFamilies=")
        ]
        self.assertEqual(families, [REQUIRED_FAMILIES])

    def test_transient_green_operator_has_identical_netlink_bootstrap_policy(self) -> None:
        source = (ROOT / "tools/deploy_runtime_dual.py").read_text(
            encoding="utf-8"
        )
        self.assertTrue(
            f'"--property={REQUIRED_FAMILIES}"' in source,
            "Transient green operator must permit exactly the WAL netlink bootstrap families",
        )


if __name__ == "__main__":
    unittest.main()
