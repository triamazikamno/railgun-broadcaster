# RAILGUN Broadcaster

A Rust implementation of a RAILGUN broadcaster that relays private transactions to Ethereum and other EVM-compatible chains.

## Features

- **Private Transaction Broadcasting**: Relay RAILGUN shielded transactions to Ethereum
- **Does not require 0zk seed phrase**: Uses view-only 0zk private key
- **Multi-Chain Support**: Configure multiple EVM chains simultaneously
- **MEV/Sandwich attack protection**: Integration with Flashbots, Bloxroute, and private RPCs
- **Dynamic Fee Management**: On-chain oracle based price feeds with configurable refresh intervals
- **Proof of Innocence (POI)**: Optional integration with RAILGUN's POI system

## Status
Project is under active development; breaking changes may occur.

### TODO
- [X] Add optional auto top-up from 0zk wallet (with implication of storing seed phrase)
- [ ] Notifications to Telegram/Discord/Matrix/Email
- [ ] Add Tor support for all external requests

## Prerequisites

### For Docker (Recommended)
- Docker 20.10+
- Docker Compose 2.0+
- Git

### For Native Build
- Rust 1.88+
- Protobuf compiler (`protoc`)
- OpenSSL development libraries
- Git

## Quick Start with Docker

```bash
# 1. Clone the repository
git clone https://github.com/triamazikamno/railgun-broadcaster.git
cd railgun-broadcaster

# 2. Copy and customize the configuration
cp config.example.yaml config.yaml
# Edit config.yaml with your settings (see Configuration section)

# 3. Create a persistent db directory
mkdir -p db

# 4. Build and run with Docker Compose
export GIT_COMMIT=$(git rev-parse --short HEAD)
export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
docker-compose up -d

# 5. View logs
docker-compose logs -f broadcaster
```

## Configuration

The broadcaster requires a `config.yaml` file with the following settings:

### Essential Configuration
See [config.example.yaml](config.example.yaml) for a complete annotated example.

### Sensitive Data in Configuration

The following fields contain sensitive information:
- `viewing_privkey`: RAILGUN view-only private key
- `evm_wallets`: Array of EVM private keys
- `api_key`: Optional Bloxroute API key

**See the Security Best Practices section below for protection measures.**

## Running with Docker

### Using Docker Compose (Recommended)

`docker-compose.yml` mounts `./db` to `/app/db` so the local database and caches
persist across restarts. Ensure `./db` exists and is writable by UID 1000.

```bash
# Build with git commit tagging
export GIT_COMMIT=$(git rev-parse --short HEAD)
export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
docker-compose build

# Start the broadcaster
docker-compose up -d

# View logs
docker-compose logs -f broadcaster

# Stop the broadcaster
docker-compose down
```

### Manual Docker Commands

```bash
# Build the image
GIT_COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

docker build \
  --build-arg GIT_COMMIT=${GIT_COMMIT} \
  --build-arg BUILD_DATE=${BUILD_DATE} \
  -t railgun-broadcaster:${GIT_COMMIT} \
  -t railgun-broadcaster:latest \
  .

# Run the container
mkdir -p db
docker run -d \
  --name railgun-broadcaster \
  --user 1000:1000 \
  -v $(pwd)/config.yaml:/app/config/config.yaml:ro \
  -v $(pwd)/db:/app/db \
  --restart unless-stopped \
  railgun-broadcaster:${GIT_COMMIT}

# View logs
docker logs -f railgun-broadcaster

# Stop and remove
docker stop railgun-broadcaster
docker rm railgun-broadcaster
```

## Running Natively

### Install Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y build-essential protobuf-compiler libssl-dev pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### macOS
```bash
brew install protobuf openssl pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build and Run

```bash
# Build the project
cargo build --release

# Run the broadcaster
./target/release/railgun-broadcaster --cfg config.yaml
```

### Logs

```bash
# Docker Compose logs
docker-compose logs -f broadcaster

# Last 100 lines
docker logs --tail 100 railgun-broadcaster
```
### Updating the Broadcaster

```bash
# Pull latest code
git pull origin main

# Rebuild with new git commit
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker-compose build

# Restart with new image
docker-compose down
docker-compose up -d
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
