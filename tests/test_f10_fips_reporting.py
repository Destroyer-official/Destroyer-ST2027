"""Regression test for F-10: Accurate FIPS 140-3 and CMVP status reporting in destroyer.py."""

import io
from contextlib import redirect_stdout
from destroyer import probe_hardware_and_environment


def test_f10_fips_status_reporting_accuracy():
    buf = io.StringIO()
    with redirect_stdout(buf):
        status = probe_hardware_and_environment()

    output = buf.getvalue()

    # Must NOT claim CMVP validation without certificate
    assert "FIPS 203/204/205 Validated" not in output

    # Must accurately describe native binary and pending CMVP status
    assert "CMVP module certificate pending" in output

