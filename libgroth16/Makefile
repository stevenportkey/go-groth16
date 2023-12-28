ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: build
build: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64

.PHONY: linux-amd64
linux-amd64:
	cargo build --target=x86_64-unknown-linux-gnu --verbose --release
	mkdir -p lib/linux/amd64
	cp target/x86_64-unknown-linux-gnu/release/libgroth16.{a,so} lib/linux/amd64

.PHONY: linux-arm64
linux-arm64:
	cross build --target=aarch64-unknown-linux-gnu --verbose --release
	mkdir -p lib/linux/arm64
	cp target/aarch64-unknown-linux-gnu/release/libgroth16.{a,so} lib/linux/arm64

.PHONY: darwin-amd64
darwin-amd64:
	cargo build --target=x86_64-apple-darwin --verbose --release
	mkdir -p lib/darwin/amd64
	cp target/x86_64-apple-darwin/release/libgroth16.{a,dylib} lib/darwin/amd64

.PHONY: darwin-arm64
darwin-arm64:
	cargo build --target=aarch64-apple-darwin --verbose --release
	mkdir -p lib/darwin/arm64
	cp target/aarch64-apple-darwin/release/libgroth16.{a,dylib} lib/darwin/arm64

.PHONY: windows-amd64
windows-amd64:
	cargo build --target=x86_64-pc-windows-gnu --verbose --release
	mkdir -p lib/windows/amd64
	cp target/x86_64-pc-windows-gnu/release/libgroth16.{a,dll} lib/windows/amd64

.PHONY: clean
clean:
	rm -rf target

.PHONY: purge
purge:
	rm -rf lib/*