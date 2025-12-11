.PHONY: release help

help:
	@echo "Available targets:"
	@echo "  release [VERSION=x.y.z]    - Release gen0sec-mcp-server: bump version, commit, tag vx.y.z, and push"
	@echo "                              If VERSION is not provided, automatically bumps patch version from latest tag"
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
