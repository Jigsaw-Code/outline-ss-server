BUILDDIR=$(CURDIR)/dist
GORELEASER=go run github.com/goreleaser/goreleaser

.PHONY: release release-local test clean clean-all

# This requires GITHUB_TOKEN to be set.
release: clean-all
	$(GORELEASER)

release-local:
	$(GORELEASER) --rm-dist --snapshot

test: third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb
	go test -v -race -bench=. ./... -benchtime=100ms

third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb:
	git submodule update --init --depth=1

go.mod: tools.go
	go mod tidy
	touch go.mod

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(CURDIR)/third_party/maxmind/*
