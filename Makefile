.PHONY: release help upgrade-nuclei

help:
	@echo "Available targets:"
	@echo "  release [VERSION=x.y.z]    - Release gen0sec-mcp-server: bump version, commit, tag vx.y.z, and push"
	@echo "                              If VERSION is not provided, automatically bumps patch version from latest tag"
	@echo "  upgrade-nuclei [COMMIT=1]  - Upgrade nuclei-templates to latest version from GitHub"
	@echo "                              Updates config.yaml and manifest.json"
	@echo "                              Set COMMIT=1 to automatically commit changes"
	@echo "  help                       - Show this help message"

release:
	@if [ -z "$(VERSION)" ]; then \
		LATEST_TAG=$$(git tag --sort=-version:refname | head -1); \
		if [ -z "$$LATEST_TAG" ]; then \
			echo "Error: No tags found. Please specify VERSION=x.y.z"; \
			exit 1; \
		fi; \
		LATEST_VERSION=$$(echo $$LATEST_TAG | sed 's/^v//'); \
		VERSION=$$(echo $$LATEST_VERSION | awk -F. '{$$NF = $$NF + 1; print $$1"."$$2"."$$3}'); \
		echo "No VERSION specified. Bumping latest tag $$LATEST_TAG to $$VERSION"; \
	else \
		VERSION=$(VERSION); \
	fi; \
	echo "Releasing gen0sec-mcp-server version $$VERSION..."; \
	sed -i.bak "s/\"version\": \".*\"/\"version\": \"$$VERSION\"/" manifest.json && rm manifest.json.bak; \
	sed -i.bak "s/^version = \".*\"/version = \"$$VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
	git add manifest.json pyproject.toml; \
	git commit -m "chore: release gen0sec-mcp-server $$VERSION"; \
	git tag v$$VERSION; \
	git push origin main; \
	git push origin tag v$$VERSION; \
	echo "Gen0Sec MCP Server version $$VERSION released successfully!"

upgrade-nuclei:
	@echo "Fetching latest nuclei-templates version from GitHub..."
	@LATEST_VERSION=$$(curl -s https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest | grep -o '"tag_name": "[^"]*' | grep -o '[^"]*$$' | head -1); \
	if [ -z "$$LATEST_VERSION" ]; then \
		echo "Error: Failed to fetch latest version from GitHub API"; \
		exit 1; \
	fi; \
	CURRENT_VERSION=$$(grep -E '^nuclei_templates_version:' server/config.yaml | sed 's/.*: *//' | tr -d ' "'); \
	if [ "$$LATEST_VERSION" = "$$CURRENT_VERSION" ]; then \
		echo "Already at latest version: $$LATEST_VERSION"; \
		exit 0; \
	fi; \
	echo "Upgrading nuclei-templates from $$CURRENT_VERSION to $$LATEST_VERSION..."; \
	sed -i.bak "s/^nuclei_templates_version:.*/nuclei_templates_version: $$LATEST_VERSION/" server/config.yaml && rm server/config.yaml.bak; \
	sed -i.bak "s/\"default\": \"v[0-9.]*\"/\"default\": \"$$LATEST_VERSION\"/" manifest.json && rm manifest.json.bak; \
	echo "Updated nuclei-templates version to $$LATEST_VERSION in:"; \
	echo "  - server/config.yaml"; \
	echo "  - manifest.json"; \
	if [ "$(COMMIT)" = "1" ]; then \
		git add server/config.yaml manifest.json; \
		git commit -m "chore: upgrade nuclei-templates to $$LATEST_VERSION"; \
		echo "Changes committed successfully!"; \
	else \
		echo "Run 'make upgrade-nuclei COMMIT=1' to commit these changes."; \
	fi
