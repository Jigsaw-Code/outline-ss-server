BUILDDIR=$(CURDIR)/dist
GOBIN=$(CURDIR)/bin
GORELEASER=$(GOBIN)/goreleaser

.PHONY: release release-local test clean clean-all

# This requires GITHUB_TOKEN to be set.
release: clean-all $(GORELEASER)
	$(GORELEASER)

release-local: $(GORELEASER)
	$(GORELEASER) --rm-dist --snapshot

test: third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb
	go test -v -race -bench=. ./... -benchtime=100ms

third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb:
	git submodule update --init

$(GORELEASER): go.mod
	env GOBIN=$(GOBIN) go install github.com/goreleaser/goreleaser

go.mod: tools.go
	go mod tidy
	touch go.mod

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(CURDIR)/third_party/maxmind/*
	rm -rf $(GOBIN)
