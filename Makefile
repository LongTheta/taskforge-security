# TaskForge Security - Development commands

.PHONY: install lint format test security run docker-build docker-up

install:
	pip install -e ".[dev]"

lint:
	ruff check app tests --fix
	ruff format app tests

format:
	ruff format app tests

test:
	pytest tests/ -v

security:
	bandit -r app -c pyproject.toml
	pip-audit --skip-editable

run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8081

docker-build:
	docker build -t taskforge-security:latest .

docker-up:
	docker-compose up --build
