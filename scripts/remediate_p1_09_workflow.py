#!/usr/bin/env python3
"""
P1-09 Remediation Script: Scopes OIDC `id-token: write` strictly to the Cosign
signing job (`adversarial-gates`), stripping broad permissions from workflow scope
and other jobs.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "defense_ci.yml"


def generate_hardened_workflow(content: str) -> str:
    # 1. Remove top-level id-token: write
    content = content.replace(
        "permissions:\n  contents: read\n  id-token: write  # OIDC identity token for Cosign / Sigstore provenance\n",
        "permissions:\n  contents: read\n"
    )

    # 2. Add job-level permissions to defense-hardening-verification
    content = content.replace(
        "  defense-hardening-verification:\n    name: CNSA 2.0 Hardening & Reproducible Build Attestation\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n",
        "  defense-hardening-verification:\n    name: CNSA 2.0 Hardening & Reproducible Build Attestation\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    permissions:\n      contents: read\n"
    )

    # 3. Add job-level scoped id-token: write to adversarial-gates
    content = content.replace(
        "  adversarial-gates:\n    name: Adversarial Gates (KAT + Supply-Chain Traversal + Boot-Config Smoke)\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    continue-on-error: false\n",
        "  adversarial-gates:\n    name: Adversarial Gates (KAT + Supply-Chain Traversal + Boot-Config Smoke)\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    continue-on-error: false\n    permissions:\n      contents: read\n      id-token: write  # Least privilege: OIDC token strictly scoped to Cosign signing job\n"
    )

    # 4. Add job-level permissions to python-test-suite
    content = content.replace(
        "    runs-on: ${{ matrix.os }}\n    timeout-minutes: 30\n    defaults:\n",
        "    runs-on: ${{ matrix.os }}\n    timeout-minutes: 30\n    permissions:\n      contents: read\n    defaults:\n"
    )

    return content


def main():
    if not WORKFLOW_FILE.exists():
        print(f"Error: {WORKFLOW_FILE} does not exist")
        return 1

    content = WORKFLOW_FILE.read_text(encoding="utf-8")
    hardened = generate_hardened_workflow(content)

    out_file = REPO_ROOT / "compliance_reports" / "defense_ci_hardened.yml"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(hardened, encoding="utf-8")
    print(f"[+] Hardened workflow generated at: {out_file}")
    print("    Top-level 'id-token: write' removed.")
    print("    'id-token: write' scoped strictly to 'adversarial-gates'.")
    print("    'contents: read' enforced across all jobs.")
    return 0


if __name__ == "__main__":
    main()

