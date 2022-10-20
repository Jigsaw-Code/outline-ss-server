# Outline ss-server
[![Build Status](https://travis-ci.org/Jigsaw-Code/outline-ss-server.svg?branch=master)](https://travis-ci.org/Jigsaw-Code/outline-ss-server)

This repository has the Shadowsocks service used by Outline servers. It uses components from [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2), and adds a number of improvements to meet the needs of the Outline users.

The Outline Shadowsocks service allows for:
- Multiple users on a single port.
  - Does so by trying all the different credentials until one succeeds.
- Multiple ports
- Whitebox monitoring of the service using [prometheus.io](https://prometheus.io)
  - Includes traffic measurements and other health indicators.
- Live updates via config change + SIGHUP
- Replay defense (add `--replay_history 10000`).  See [PROBES](service/PROBES.md) for details.

![Graphana Dashboard](https://user-images.githubusercontent.com/113565/44177062-419d7700-a0ba-11e8-9621-db519692ff6c.png "Graphana Dashboard")

## Try it!

Fetch dependencies for this demo:
```
GO111MODULE=off go get github.com/shadowsocks/go-shadowsocks2 github.com/prometheus/prometheus/cmd/...
```

On Terminal 1, from the repository directory, build and start the SS server:
```
go run . -config config_example.yml -metrics localhost:9091
```

On Terminal 2, start prometheus scraper for metrics collection:
```
$(go env GOPATH)/bin/prometheus --config.file=prometheus_example.yml
```

On Terminal 3, start the SS client:
```
$(go env GOPATH)/bin/go-shadowsocks2 -c ss://chacha20-ietf-poly1305:Secret0@:9000 -verbose  -socks localhost:1080
```

On Terminal 4, fetch a page using the SS client:
```
curl --proxy socks5h://localhost:1080 example.com
```

Stop and restart the client on Terminal 3 with "Secret1" as the password and try to fetch the page again on Terminal 4.

Open http://localhost:9091/metrics and see the exported Prometheus variables.

Open http://localhost:9090/ and see the Prometheus server dashboard.


## Performance Testing

Start the iperf3 server (runs on port 5201 by default):
```
iperf3 -s
```

Start the SS server (listening on port 9000):
```
go run . -config config_example.yml
```

Start the SS tunnel to redirect port 8000 -> localhost:5201 via the proxy on 9000:
```
$(go env GOPATH)/bin/go-shadowsocks2 -c ss://chacha20-ietf-poly1305:Secret0@:9000 -tcptun ":8000=localhost:5201" -udptun ":8000=localhost:5201" -verbose
```

Test TCP upload (client -> server):
```
iperf3 -c localhost -p 8000
```

Test TCP download (server -> client):
```
iperf3 -c localhost -p 8000 --reverse
```

Test UDP upload:
```
iperf3 -c localhost -p 8000 --udp -b 0
```

Test UDP download:
```
iperf3 -c localhost -p 8000 --udp -b 0 --reverse
```

### Compare to go-shadowsocks2

Run the commands above, but start the SS server with
```
$(go env GOPATH)/bin/go-shadowsocks2 -s ss://chacha20-ietf-poly1305:Secret0@:9000 -verbose
```


### Compare to shadowsocks-libev 

Start the SS server (listening on port 10001):
```
ss-server -s localhost -p 10001 -m chacha20-ietf-poly1305 -k Secret1 -u -v
```

Start the SS tunnel to redirect port 10002 -> localhost:5201 via the proxy on 10001:
```
ss-tunnel -s localhost -p 10001 -m chacha20-ietf-poly1305 -k Secret1 -l 10002 -L localhost:5201 -u -v
```

Run the iperf3 client tests listed above on port 10002.

You can mix and match the libev and go servers and clients.

## Tests and Benchmarks

Before running tests, you should first run
```
git submodule update --init
```
to download test data used by the GeoIP metrics tests.  To run all tests, you can use
```
go test -v ./...
```

You can benchmark the cipher finding code with
```
go test -cpuprofile cpu.prof -memprofile mem.prof -bench . -benchmem -run=^$ github.com/Jigsaw-Code/outline-ss-server/shadowsocks
```

You can inspect the CPU or memory profiles with `go tool pprof cpu.prof` or `go tool pprof mem.prof`, and then enter `web` on the prompt.

## Release

We use [GoReleaser](https://goreleaser.com/) to build and upload binaries to our [GitHub releases](https://github.com/Jigsaw-Code/outline-ss-server/releases).

Summary:
- Test the build locally:
  ```
  make release-local
  ```
- Export an environment variable named `GITHUB_TOKEN` with a repo-scoped GitHub token ([create one here](https://github.com/settings/tokens/new)):
  ```bash
  export GITHUB_TOKEN=yournewtoken
  ```
- Create a new tag and push it to GitHub e.g.:
  ```bash
  git tag v1.0.0
  git push origin v1.0.0
  ```
- Build and upload:
  ```bash
  goreleaser
  ```
- Go to https://github.com/Jigsaw-Code/outline-ss-server/releases, review and publish the release.

Full instructions in [GoReleaser's Quick Start](https://goreleaser.com/quick-start) (jump to the section starting "You’ll need to export a GITHUB_TOKEN environment variable").
