# Makefile for seL4 Microkit MILS Domain Separation Appliance
# Target Security Standards: Common Criteria EAL6+ / EAL7 Equivalent

CARGO ?= cargo
PYTHON ?= python

.PHONY: all check aarch64 test verify clean

all: check aarch64 test verify

# Check compilation of all three bare-metal domains
check:
	$(CARGO) check --manifest-path Cargo.toml
	$(CARGO) check --release --manifest-path Cargo.toml
	$(CARGO) check --target aarch64-unknown-none --release --manifest-path Cargo.toml

# Build bare-metal AArch64 ELF binaries
aarch64:
	$(CARGO) build --target aarch64-unknown-none --release --manifest-path Cargo.toml

# Run bare-metal Rust unit tests
test:
	$(CARGO) test --manifest-path Cargo.toml

# Formally verify MILS invariants via static assertion suite
verify:
	$(PYTHON) -m pytest ../tests/test_sel4_mils_spec.py -v
	$(PYTHON) validate_mils.py --strict

# Clean build artifacts
clean:
	$(CARGO) clean --manifest-path Cargo.toml
