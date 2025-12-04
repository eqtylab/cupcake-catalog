# Cupcake Catalog Documentation

This directory contains the documentation site for Cupcake Catalog.

## Development

```bash
# Install dependencies
uv sync

# Start development server
uv run zensical serve

# Build static site
uv run zensical build
```

## Structure

```
docs/
  docs/           # Markdown content
    index.md      # Home page
    getting-started/
    authoring/
    reference/
  overrides/      # Template overrides
  zensical.toml   # Site configuration
  pyproject.toml  # Python dependencies
```

## Deployment

The site is automatically deployed to GitHub Pages when changes are pushed to the main branch.
