.DEFAULT_GOAL := help
.PHONY: help install sync lint format fmt typecheck check fix run clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} \
		/^## / {printf "\n\033[1m%s\033[0m\n", substr($$0, 4); next} \
		/^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run: ## Run the CLI (pass args with ARGS="...")
	uv run mega-cli $(ARGS)

clean: ## Remove caches and build artifacts
	rm -rf .ruff_cache .mypy_cache dist build
	find . -type d -name __pycache__ -exec rm -rf {} +

## Setup
install: ## Create the venv and install all deps (incl. dev group)
	uv sync --all-groups

sync: ## Sync deps exactly from the lockfile
	uv sync --locked --all-groups

## Lint & Checks
lint: ## Run ruff lint checks
	@uv run ruff check || { printf '\033[31mRun "make fix"\033[0m\n' >&2; exit 1; }

format: ## Check formatting without writing changes
	@uv run ruff format --check || { printf '\033[31mRun "make fix"\033[0m\n' >&2; exit 1; }

typecheck: ## Run mypy in strict mode
	uv run mypy src

check: lint format typecheck ## Run everything CI runs

## Fix Lint & Check findings
fmt: ## Apply formatting
	uv run ruff format

fix: fmt ## Auto-fix lint issues and format
	uv run ruff check --fix
