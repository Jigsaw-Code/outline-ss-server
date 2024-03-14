BUILDDIR=$(CURDIR)/dist
GORELEASER=go run github.com/goreleaser/goreleaser

.PHONY: release release-local test clean

# This requires GITHUB_TOKEN to be set.
release: clean
	$(GORELEASER)

release-local:
	$(GORELEASER) --clean --snapshot

test: third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb
	go test -v -race -benchmem -bench=. ./... -benchtime=100ms

third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb:
	git submodule update --init --depth=1

go.mod: tools.go
	go mod tidy
	touch go.mod

clean:
	rm -rf $(BUILDDIR)
	go clean
