package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/Jigsaw-Code/outline-ss-server/caddy"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/mholt/caddy-l4"
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4http"
)

func main() {
	caddycmd.Main()
}
