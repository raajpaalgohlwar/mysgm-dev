# mysgm

## Repository overview

This repository hosts a Rust CLI application for secure group messaging built on OpenMLS, along with Docker assets to run a local OpenDHT node and to cross-compile the CLI for Raspberry Pi. The core runtime lives in `workspace/mysgm`, while OpenDHT/OpenMLS sources are vendored in `workspace/opendht` and `workspace/openmls` for local builds and container images. See [TESTBED.md](./TESTBED.md) for testbed setup instructions.


### Top-level layout

- `README.md`: This overview document.
- `TESTBED.md`: Testbed set-up.
- `LICENSE`: Licensing information.
- `mysgm-test/compose.yml`: Docker Compose file that starts an OpenDHT node + REST proxy and the optional cross-compile builder service for Raspberry Pi binaries.【F:mysgm-test/compose.yml†L1-L20】
- `workspace/`: Monorepo-style workspace holding the Rust CLI, OpenDHT sources, OpenMLS sources, and the Docker builder image.

### `workspace/mysgm` (Rust CLI application)

`workspace/mysgm` is the production CLI binary. The entrypoint is `src/main.rs`, which wires together adapters, OpenMLS configuration, and CLI commands. The process flow is:

1. Parse CLI args (state file, adapter, and subcommand).
2. Initialize or load local state (`state_path`).
3. Sync from the chosen adapter (download key packages, welcomes, commits).
4. Execute the requested subcommand (advertise, create group, add/remove/update, etc.).
5. Persist updated state to disk.

#### `workspace/mysgm/src/main.rs`

- Defines all CLI flags and subcommands via `clap`, including adapter selection (`--adapter file|dht`), DHT host/port, and group commands like `CreateGroup`, `Advertise`, and `Group Add/Remove/Update`.
- Constructs the selected adapter, loads or resets state, and then pulls key packages, welcomes, and commits from the adapter before executing the chosen command.
- Implements group actions such as exporting secrets, listing members, adding/removing members, and updating self state. These actions generate commits/welcomes and write them to the adapter for other agents to consume.

#### `workspace/mysgm/src/state.rs`

- Stores the agent’s persistent state (PID, key packages, group IDs, counters, and OpenMLS storage).
- Implements the OpenMLS storage traits via an internal key-value store so MLS groups and secrets can be loaded/stored across runs.
- Serialized to the JSON file passed as `state_path` and reloaded on startup.

#### Agent state JSON (`agentX.json`) contents

The `state_path` JSON file (for example, `agent1.json`) is a serialized `MySgmState` and is the canonical on-disk state for each node. It is created on `--reset` and rewritten on each run after processing inbound data and executing a command.

Key fields you should expect to see:

- `pid`: The local agent identifier (e.g., `agent_a63`).
- `signature_key_pair`: The long-term signing keypair (private/public key bytes and signature scheme)
- `mls_version`: MLS protocol version in use (currently `Mls10`).
- `my_ciphersuite`: MLS ciphersuite used for group operations.
- `welcome_counter` / `key_package_counter`: Offsets used to fetch welcome and key package records from the adapter on startup.
- `key_packages`: Map of known key packages keyed by PID; populated from downloaded key packages and used when adding members to a group.【F:workspace/mysgm/src/main.rs†L145-L167】【F:workspace/mysgm/src/main.rs†L555-L565】
- `gids`: List of group IDs this node has joined; populated when a welcome is processed successfully.【F:workspace/mysgm/src/main.rs†L169-L238】
- `openmls_values`: The OpenMLS storage map (group context, tree, secrets, epoch state, etc.) required to load and advance MLS groups across runs.【F:workspace/mysgm/src/state.rs†L1-L1025】

#### `workspace/mysgm/src/provider.rs`

- Bridges OpenMLS with local state and crypto by implementing `OpenMlsProvider` and `Signer` for the app’s provider type.
- Exposes the OpenMLS storage adapter, crypto provider, and randomness provider required by OpenMLS operations.【F:workspace/mysgm/src/provider.rs†L1-L56】

#### `workspace/mysgm/src/opendht.rs`

- Implements the OpenDHT REST adapter used when `--adapter dht` is selected.
- Performs HTTP `GET`/`POST` to the REST proxy to read/write key packages, welcomes, and commits across devices.【F:workspace/mysgm/src/opendht.rs†L1-L78】

#### `workspace/mysgm/src/file_adapter.rs`

- Implements a file-backed adapter used when `--adapter file` is selected.
- Persists each key as a hex-encoded file in a directory, which is useful for local testing without a DHT node.【F:workspace/mysgm/src/file_adapter.rs†L1-L35】

#### `workspace/mysgm/src/keys.rs`

- Defines signature key types used by OpenMLS credentials, including a custom `SignatureKeyPair` wrapper.
- Handles key generation via OpenMLS crypto traits and provides accessors for raw key bytes.【F:workspace/mysgm/src/keys.rs†L1-L178】

### `workspace/opendht` (OpenDHT sources)

This directory contains the OpenDHT sources that are used by the `dht` service in `mysgm-test/compose.yml`. The Docker build spins up a local DHT node plus the REST proxy, which backs the `--adapter dht` workflow for sharing key packages, welcomes, and commits across devices.【F:mysgm-test/compose.yml†L11-L20】

### `workspace/openmls` (OpenMLS sources)

This directory contains the OpenMLS sources that the Rust CLI depends on for MLS group creation, membership management, and commit/welcome processing. The CLI uses OpenMLS types throughout `main.rs` and relies on these vendored sources for builds.

### `workspace/Dockerfile.builder` (Pi cross-compile image)

Defines a Rust build environment that installs the ARM64 toolchain and linker so you can build `mysgm` for Raspberry Pi without local toolchain setup. This image is used by the `mysgm_builder` service in `mysgm-test/compose.yml`.【F:workspace/Dockerfile.builder†L1-L15】【F:mysgm-test/compose.yml†L3-L10】

## Using this overview

If you’re new to the codebase, start with `workspace/mysgm/src/main.rs` to understand CLI behavior and the startup sync flow. Then read `state.rs` and `provider.rs` to see how agent state and OpenMLS storage are managed. The adapters (`opendht.rs` and `file_adapter.rs`) show how state is shared between nodes, and `keys.rs` documents how identities are generated.
