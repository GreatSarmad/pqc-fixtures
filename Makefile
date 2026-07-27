BINARY := pqc-fixtures
BUILD_DIR := bin
ENGINE_DIR := dist/engine

.PHONY: build test fmt lint clean engine verify-engine

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

fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

lint: fmt
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
