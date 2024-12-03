# Caddy Module

The Caddy module provides an app and handler for Caddy Server
(https://caddyserver.com/) allowing it to turn any Caddy Server into an Outline
Shadowsocks backend.

## Prerequisites

- [xcaddy](https://github.com/caddyserver/xcaddy)

## Usage

From this directory, build and run a custom binary with `xcaddy`:

```sh
xcaddy run --config config_example.json --watch
```

In a separate window, confirm you can fetch a page using this server:

```sh
go run github.com/Jigsaw-Code/outline-sdk/x/examples/fetch -transport "ss://chacha20-ietf-poly1305:Secret1@:9000" http://ipinfo.io
```

Prometheus metrics are available on http://localhost:9091/metrics.
