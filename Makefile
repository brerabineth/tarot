ZIG ?= zig

.PHONY: build test e2e clean

build:
	$(ZIG) build -Doptimize=ReleaseSafe

test:
	$(ZIG) build test

e2e: build
	bash test/e2e_local.sh

clean:
	rm -rf zig-out .zig-cache
