BINARY := pqc-fixtures
BUILD_DIR := bin
ENGINE_DIR := dist/engine

.PHONY: build test test-engine fmt lint clean engine verify-engine

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./src/cmd/pqc-fixtures

# Builds the pinned OpenSSL engine (ADR-001) from source into dist/engine.
# Takes several minutes; only needed to run the tool end-to-end locally or to
# validate a pin bump. `make build` and `make test` do not require it.
engine:
	scripts/build-openssl.sh --out $(ENGINE_DIR)

verify-engine:
	scripts/verify-openssl.sh $(ENGINE_DIR)/openssl \
		$$(sed -n 's/^OPENSSL_VERSION=//p' scripts/openssl-pin.env)

test:
	go test ./...

# Same suite, but with the engine tests actually running rather than skipping.
# The acceptance criteria about bytes on disk (chain verification, size
# fidelity, manifest hashes) only mean anything against a real engine, so CI
# runs this on every supported platform after building the pinned engine.
test-engine: $(ENGINE_DIR)/openssl
	PQC_FIXTURES_OPENSSL=$(CURDIR)/$(ENGINE_DIR)/openssl go test ./... -count=1

$(ENGINE_DIR)/openssl:
	@echo "no engine at $@; run 'make engine' first" >&2; exit 1

fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

lint: fmt
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
