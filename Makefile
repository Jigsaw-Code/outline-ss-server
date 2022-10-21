BUILDDIR=$(CURDIR)/build
GOBIN=$(CURDIR)/bin
GORELEASER=$(GOBIN)/goreleaser

.PHONY: release-local test clean clean-all

release-local:
	$(GORELEASER) --rm-dist --snapshot

test:
	go test -v ./...

$(GORELEASER): go.mod
	env GOBIN=$(GOBIN) go install github.com/goreleaser/goreleaser

go.mod: tools.go
	go mod tidy
	touch go.mod

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(GOBIN)
	