.PHONY: format
format:
	@echo "Running formatter..."
	@cargo fmt --all

.PHONY: format-check
format-check:
	@echo "Running formatter..."
	@cargo fmt --all -- --check

.PHONY: lint
lint:
	@echo "Running linter..."
	@cargo clippy --all-targets --all-features -- -D warnings

.PHONY: check
github-checks: format-check lint
	@echo "Running tests..."
	@cargo test --all --all-features -- --nocapture
