# mysgm-dev

## 1) Initialize a Raspberry Pi 4 Model B

The model used for this research was the Raspberry Pi 4 Model B. Use this once per Pi to get a clean, repeatable baseline before installing `mysgm`. See [README.md](./README.md) for codebase overview and usage.

1. **Install Raspberry Pi OS (64-bit)**  
   Use Raspberry Pi Imager to flash the latest 64-bit Raspberry Pi OS onto a microSD card. Enable SSH and set a hostname in the advanced options.
   
2. **First boot + system update**  
   Boot the Pi, SSH in, and update packages:

   ```bash
   sudo apt update
   sudo apt -y full-upgrade
   sudo reboot
   ```
3. **Install required packages**  
   After reboot, install baseline tools:

   ```bash
   sudo apt install -y ca-certificates curl
   ```
   
## 2) Start the Docker Containers

From the repository root, use the `mysgm-test/compose.yml` file to start the DHT node and the cross-compile builder container.

```bash
docker compose -f mysgm-test/compose.yml up -d dht
```

This exposes the OpenDHT REST proxy on host port `8000` and the DHT UDP port on `4222` as defined in the compose file.

If you want to build the Pi binary via Docker, the same compose file includes the `mysgm_builder` service (see next section).

## 3) Raspberry Pi Binary Build and Installation

### Option A: Build with Docker (recommended)

The repository ships a cross-compile builder image (`workspace/Dockerfile.builder`) that installs the `aarch64-unknown-linux-gnu` toolchain and linker for Raspberry Pi builds.

Run the build service:

```bash
# from repo root

docker compose -f mysgm-test/compose.yml run --name mysgm_builder mysgm_builder
```

Copy the binary out of the builder container (path inside the container is `/tmp/target/...`):

```bash
docker cp mysgm_builder:/tmp/target/aarch64-unknown-linux-gnu/release/mysgm ./mysgm-aarch64
```

Clean up the container:

```bash
docker rm mysgm_builder
```

### Option B: Build locally (if you already have a cross toolchain)

```bash
# from workspace/mysgm
cargo build --release --target aarch64-unknown-linux-gnu
```

The binary will be at:

```
workspace/mysgm/target/aarch64-unknown-linux-gnu/release/mysgm
```

### Install on each Raspberry Pi

Copy the binary and make it executable:

```bash
scp mysgm pi@<PI_HOST>:/home/pi
ssh pi@<PI_HOST>
chmod +x mysgm
```

## 4) CLI Arguments

The CLI is defined in `workspace/mysgm/src/main.rs` and uses a positional `state_path` plus optional flags and subcommands.

### Positional argument

- `state_path` (required): Path to the JSON file used to store local agent state. This file is read on startup and written on exit.

### Global flags

- `--reset`: Reset local state and generate a new PID/identity.
- `--pid <string>`: Prefix used when generating the PID on reset (default: `agent`).
- `--adapter <file|dht>`: Storage adapter for sharing state (default: `file`). Use `dht` when you want multiple nodes to share key packages/welcomes/commits via the REST proxy.【
- `--file-path <path>`: Directory for file adapter storage (default: `/tmp`).
- `--dht-host <host>`: Hostname or IP for the OpenDHT REST proxy (default: `localhost`). For multi-host setups, this should be the machine running the proxy (e.g., your controller’s IP).
- `--dht-port <port>`: REST proxy port (default: `8000`).

### Top-level commands

- `Me`: Print your local PID (agent identifier).
- `Agents`: List all known agent PIDs in local state (populated by downloaded key packages).
- `Groups`: List groups in local state (populated by processed welcomes).
- `Advertise`: Publish your key package to the selected adapter (DHT when `--adapter dht`).
- `CreateGroup --gid <name>`: Create a group locally; the CLI will suffix the gid with a short key identifier to avoid collisions.
- `Group <gid> <subcommand>`: Operate on a specific group ID.

### Group subcommands

- `Group <gid> ExportSecret --label <label> --length <len>`: Export a secret for the group by label/length.
- `Group <gid> Members`: List group members with their leaf indexes and PIDs.
- `Group <gid> Add [pid ...]`: Add members by PID. If you don’t pass PIDs, it reads one per line from stdin.
- `Group <gid> Remove [index ...]`: Remove members by leaf index. If you don’t pass indexes, it reads one per line from stdin.
- `Group <gid> Update`: Perform a self-update and publish the commit (and welcome if emitted).

## 5) Quickstart (controller + Pi sequence)

Use the DHT adapter on all devices so key packages, welcomes, and commits are shared.

1. **On each Pi: publish a key package**

   ```bash
   mysgm /var/lib/mysgm/pi.json --adapter dht --dht-host <DHT_HOST> --dht-port 8000 advertise
   ```

2. **On the controller: create a group**

   ```bash
   GROUP_ID=$(mysgm controller.json --adapter dht --dht-host <DHT_HOST> --dht-port 8000 CreateGroup --gid group1)
   echo "$GROUP_ID"
   ```

3. **On the controller: add Pi members by PID**

   ```bash
   mysgm controller.json --adapter dht --dht-host <DHT_HOST> --dht-port 8000 \
     Group "$GROUP_ID" Add <PID_PI_1> <PID_PI_2> <PID_PI_3> <PID_PI_4>
   ```

4. **On each Pi: sync welcomes/commits**

   ```bash
   mysgm /var/lib/mysgm/pi.json --adapter dht --dht-host <DHT_HOST> --dht-port 8000 Groups
   ```

## 6) DHT troubleshooting

- **Check REST proxy logs** (from the host running Docker):

  ```bash
  docker compose -f mysgm-test/compose.yml logs --tail 200 dht
  ```

- **Common issue: 502 on POST**  
  A `502 Bad Gateway` on `POST /key/...` usually means the proxy couldn’t complete the write even though the DHT may still store the value. Retrying `advertise` often succeeds.

## 7) State file defaults

Each device requires a local state file. A consistent default is:

```
/var/lib/mysgm/<agent>.json
```

## 8) Security / ops notes

The DHT REST proxy is unauthenticated by default. Restrict access to `8000` (e.g., firewall rules or private network access) when running on shared networks.