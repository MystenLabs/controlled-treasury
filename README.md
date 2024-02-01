# controlled-treasury

An example smart contract to manage a controlled treasury with flexible risk-management controls.

Build and run tests:
```bash
# build the treasury package
sui move build --path treasury

# tests are a separate package with Move 2024 (requires build from `main`)
sui move test --path tests
```

## Notes on Tests

Tests use Move 2024 and require a custom build of the Move compiler from `main` branch.
