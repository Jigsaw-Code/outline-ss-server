# Caddy Module

The Caddy module provides an app and handler for Caddy Server
(https://caddyserver.com/) allowing it to turn any Caddy Server into an Outline
Shadowsocks backend.

## Prerequisites

- [xcaddy](https://github.com/caddyserver/xcaddy)

## Usage

From this directory, build and run a custom Caddy binary with this Go module plugged in using `xcaddy`:

```sh
xcaddy build \
  --with github.com/iamd3vil/caddy_yaml_adapter \
  --with github.com/mholt/caddy-l4 \
  --with github.com/Jigsaw-Code/outline-ss-server/caddy
./caddy run --config caddy/examples/simple.yaml --adapter yaml --watch
```

In a separate window, confirm you can fetch a page over Shadowsocks:

```sh
go run github.com/Jigsaw-Code/outline-sdk/x/examples/fetch \
  -transport "ss://chacha20-ietf-poly1305:Secret1@:9000" \
  http://ipinfo.io
```

Prometheus metrics are available on http://localhost:9091/metrics.

## Development

From the repo's root directory, run the Caddy module directly from Go:

```sh
go run -tags nomysql ./cmd/caddy run --adapter yaml --config caddy/examples/simple.yml --watch
```
