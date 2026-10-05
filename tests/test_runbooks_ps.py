"""PowerShell runbooks mirror the .sh gates — static lock-in (cross-platform).

Runs on any OS: asserts scripts/setup_tor_overlay.ps1 and
scripts/setup_wireguard.ps1 exist and enforce the same fail-closed
semantics as their .sh twins, so a future edit cannot silently drop a gate.
Live fail-closed behaviour (EXIT=1 without daemons) is proven manually on
Windows: tor overlay refuses without tor daemon, wg refuses without iface.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent if pathlib.Path(__file__).resolve().parent.name == "tests" else pathlib.Path(__file__).resolve().parent
TOR_PS = ROOT / "scripts" / "setup_tor_overlay.ps1"
WG_PS = ROOT / "scripts" / "setup_wireguard.ps1"


class TestPowerShellRunbooks(unittest.TestCase):
    def test_tor_runbook_gates(self):
        src = TOR_PS.read_text(encoding="utf-8")
        # daemon + PT bundle presence
        self.assertIn("tor daemon not installed", src)
        self.assertIn("lyrebird", src)
        # live SOCKS5 greeting against the proxy (mirrors check_tor_proxy_live)
        self.assertIn("0x05", src)
        self.assertIn("SOCKS5 greeting refused", src)
        # runtime torrc PT enforcement (mirrors torrc_enforces_pt)
        self.assertIn("P2P_TOR_PT", src)
        self.assertIn("UseBridges", src)
        self.assertIn("ClientTransportPlugin", src)
        # fail-closed helper present
        self.assertIn("TOR-OVERLAY-FAIL", src)

    def test_wg_runbook_gates(self):
        src = WG_PS.read_text(encoding="utf-8")
        self.assertIn("P2P_WG_IFACE", src)
        self.assertIn("P2P_PEER_PREFIX", src)
        self.assertIn("wireguard tools missing", src)
        self.assertIn("latest handshake", src)
        self.assertIn("prefixlen<=64", src)
        self.assertIn("WG-OVERLAY-FAIL", src)

    def test_sh_twins_still_present(self):
        # .ps1 must not replace .sh — both provision paths ship together.
        self.assertTrue((ROOT / "scripts" / "setup_tor_overlay.sh").exists())
        self.assertTrue((ROOT / "scripts" / "setup_wireguard.sh").exists())

    def test_both_runbooks_ask_elevation_never_take(self):
        # Admin is requested with consent + UAC relaunch; declining or
        # non-interactive shells continue with a warning (gates enforce).
        for path in (TOR_PS, WG_PS):
            src = path.read_text(encoding="utf-8")
            self.assertIn("IsInRole", src)
            self.assertIn("-Verb RunAs", src)
            self.assertIn("P2P_NO_ELEVATE", src)
            self.assertIn("continuing without elevation", src)


if __name__ == "__main__":
    unittest.main()
