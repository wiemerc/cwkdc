.PHONY: all setup pretty checks
SHELL := /usr/bin/zsh

all: pretty checks

setup:
	uv init --app --name cwkrbd --description "Proof-of-concept for a Kerberos server" --no-readme --no-workspace --author-from git
	uv add -r requirements.txt

pretty:
	ruff format **/*.py
	ruff check --select I --fix **/*.py

checks:
	ty check --python ./.venv-fastapi/bin/python **/*.py
	ruff check
