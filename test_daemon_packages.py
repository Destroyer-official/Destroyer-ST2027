"""Daemon configuration packages: torrc template, wg template, systemd unit.

Locks in Task-2 deliverables and the fail-closed rule that NEITHER overlay
runbook (.sh or .ps1) may pass a copied-but-unfilled template: every
__OPERATOR_*__ placeholder requires a site value before the pipeline's
require_overlay gate can go live. Static (cross-platform); live daemon
behavior is proven on hardened endpoints by the runbooks themselves.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
TORRC = ROOT / "scripts" / "tor" / "torrc.ts-hardened"
TOR_UNIT = ROOT / "scripts" / "tor" / "secure-transmit-tor.service"
WG_TMPL = ROOT / "scripts" / "wireguard" / "wg-ts0.conf.template"
SH_TOR = ROOT / "scripts" / "setup_tor_overlay.sh"
SH_WG = ROOT / "scripts" / "setup_wireguard.sh"
PS_TOR = ROOT / "scripts" / "setup_tor_overlay.ps1"
PS_WG = ROOT / "scripts" / "setup_wireguard.ps1"


class TestTorPackage(unittest.TestCase):
    def test_torrc_is_client_only_and_censorship_mandatory(self):
        src = TORRC.read_text(encoding="utf-8")
        self.assertIn("SocksPort 127.0.0.1:9050", src)
        self.assertIn("UseBridges 1", src)
        self.assertIn("ClientTransportPlugin obfs4", src)
        self.assertIn("ClientTransportPlugin webtunnel", src)
        self.assertIn("AvoidDiskWrites 1", src)
        self.assertIn("StrictNodes 1", src)
        for token in ("SocksPort 9050\n", "ORPort", "ExitRelay 1", "HiddenServiceDir"):
            if token == "SocksPort 9050\n":
                continue  # bound form above is required, bare form forbidden
            self.assertNotIn(token, src)
        # No real secrets ship: only placeholders.
        self.assertIn("__OPERATOR_BRIDGE_1__", src)
        self.assertIn("__OPERATOR_LYREBIRD_PATH__", src)
        self.assertNotIn("cert=", src.split("# __OPERATOR_BRIDGE_1__")[0].split(
            "ClientTransportPlugin")[0])

    def test_torrc_has_no_bare_socksport(self):
        lines = [ln.split("#")[0].strip() for ln in
                 TORRC.read_text(encoding="utf-8").splitlines()]
        live = [ln for ln in lines if ln]
        self.assertFalse(any(ln == "SocksPort 9050" for ln in live))
        self.assertTrue(any(ln.startswith("SocksPort 127.0.0.1:9050") for ln in live))

    def test_systemd_unit_guards_placeholders(self):
        src = TOR_UNIT.read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/bin/tor -f /etc/tor/tor-ts/torrc", src)
        self.assertIn("__OPERATOR_", src)  # pre-start placeholder refusal
        self.assertIn("NoNewPrivileges=true", src)
        self.assertIn("ProtectSystem=strict", src)

    def test_both_tor_runbooks_reject_unfilled_template(self):
        self.assertIn("__OPERATOR_", SH_TOR.read_text(encoding="utf-8"))
        self.assertIn("__OPERATOR_", PS_TOR.read_text(encoding="utf-8"))


class TestWireGuardPackage(unittest.TestCase):
    def test_wg_template_shape(self):
        src = WG_TMPL.read_text(encoding="utf-8")
        self.assertIn("[Interface]", src)
        self.assertIn("[Peer]", src)
        self.assertIn("PrivateKey = __OPERATOR_PRIVATE_KEY_B64__", src)
        self.assertIn("AllowedIPs = __OPERATOR_PEER_PREFIX__", src)
        self.assertIn("PersistentKeepalive", src)
        self.assertIn("Table = off", src)
        # Template ships placeholders only: 44-char base64 key would be real.
        import re
        for line in src.splitlines():
            live = line.split("#")[0]
            if "PrivateKey" in live or "PublicKey" in live:
                self.assertIn("__OPERATOR_", live)

    def test_both_wg_runbooks_require_ipv6_prefix_and_handshake(self):
        for path in (SH_WG, PS_WG):
            src = path.read_text(encoding="utf-8")
            self.assertIn("P2P_PEER_PREFIX", src)
            self.assertIn("latest handshake", src)


if __name__ == "__main__":
    unittest.main()
