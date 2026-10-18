GO      ?= go
LDFLAGS := -trimpath -ldflags "-s -w"
SRC     := $(wildcard cmd/*/*.go) $(wildcard internal/*/*.go) go.mod go.sum

# Prebuilt loaders, one per supported platform. self embeds these
# gzipped assets at build time and picks one by the target's format;
# gzip -n keeps the embedded bytes reproducible.
STUBS          := internal/stubs/assets
STUB_PLATFORMS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-386
STUB_ASSETS    := $(addprefix $(STUBS)/stub-,$(addsuffix .gz,$(STUB_PLATFORMS)))

.PHONY: all stub stubs self test clean

all: self

stub: build/stub

stubs: $(STUB_ASSETS)

self: build/self

$(STUBS)/stub-%.gz: $(SRC)
	@mkdir -p $(STUBS)
	@set -e; p=$*; \
		GOOS=$${p%-*} GOARCH=$${p##*-} CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $@.bin ./cmd/stub; \
		gzip -9n -c $@.bin > $@.tmp; \
		mv $@.tmp $@; \
		rm -f $@.bin

build/stub: $(SRC)
	@mkdir -p build
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $@ ./cmd/stub

build/self: $(SRC) $(STUB_ASSETS)
	@mkdir -p build
	$(GO) build $(LDFLAGS) -o $@ ./cmd/self

test:
	$(GO) vet ./...
	$(GO) test -count=1 ./...

clean:
	rm -rf build dist
	rm -f $(STUB_ASSETS)
