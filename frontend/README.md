# BEACON frontend

React and Vite frontend for BEACON. See the [project README](../README.md) for architecture, setup requirements, and current limitations.

## Development

Install the locked dependencies with `npm ci` from this directory. Review `package.json` for available development, lint, and build commands.

Run the frontend checks from this directory:

```bash
BEACON_COMPOSE_PATH=../compose.yaml node --test tests/*.test.mjs
```

The frontend requires the BEACON backend and configured authentication services for complete workflows. Passing source-level tests does not replace browser acceptance testing.
