.PHONY: test test-watch types types-clean clean install up down down-volumes logs help

test: ## Run tests
	npx vitest --reporter=verbose --run

test-watch: ## Run tests in watch mode
	npx vitest

types: ## Generate .d.ts from jsdoc
	npx tsc --declaration --allowJs --emitDeclarationOnly --skipLibCheck \
		--target es2020 --module nodenext --moduleResolution nodenext \
		--strict false --esModuleInterop true --outDir ./types src/index.js

types-clean: ## Remove generated types
	rm -rf types

clean: ## Remove node_modules
	rm -rf node_modules

install: ## Install dependencies
	npm install

up: ## Start postgres
	docker compose up -d

down: ## Stop postgres
	docker compose down

down-volumes: ## Stop postgres and wipe data
	docker compose down -v

logs: ## Tail postgres logs
	docker compose logs -f

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-20s\033[0m %s\n", $$1, $$2}'
