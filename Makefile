GO ?= go
STATICCHECK_VERSION ?= v0.8.2

.PHONY: all build test race vet fmt fmt-check lint check fuzz site clean

all: check build

build:
	$(GO) build -o bin/opfence ./cmd/opfence

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -s -w .

fmt-check:
	@out="$$(gofmt -s -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

# Run every fuzz target for FUZZTIME each (default 30s).
FUZZTIME ?= 30s
fuzz:
	@for pkg in $$($(GO) list ./...); do \
	  for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
	    echo "== $$pkg $$f"; $(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	  done; \
	done

check: fmt-check vet race

# The documentation site, written to _site/ (tools/sitegen is its own module,
# so the opfence binary does not depend on a Markdown renderer).
site:
	cd tools/sitegen && $(GO) run . -repo ../.. -out ../../_site

clean:
	rm -rf bin dist _site
