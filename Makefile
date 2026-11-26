.PHONY: build test race vet integration bench setcap install uninstall man-check man-md dist clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man
LDFLAGS := -s -w -X github.com/hotid/mpmtr/internal/cli.Version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags='$(LDFLAGS)'
MANPAGES := mpmtr.1 mpmtr-app-http.1 mpmtr-hop-snmp.1

build:
	$(GOBUILD) -o mpmtr-app-http ./cmd/mpmtr-app-http
	$(GOBUILD) -o mpmtr-hop-snmp ./cmd/mpmtr-hop-snmp
	$(GOBUILD) -o mpmtr .

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...
	go vet -tags integration ./integration/
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo 'gofmt: files above need formatting'; exit 1; }

# Needs root: creates network namespaces mpsrc/mpr0..4/mprd/mpdst.
integration: build
	cd integration && go test -c -tags integration -o ../integration.test .
	cd integration && sudo MPMTR_BIN=$(CURDIR)/mpmtr ../integration.test -test.v -test.count=1 -test.timeout 60m
	rm -f integration.test

bench:
	go test -run xxx -bench . -benchmem ./internal/...

# Grant the capabilities to the binary in the source tree (re-run after every
# build: a new file has none).
setcap: build
	sudo setcap cap_net_raw,cap_net_admin+ep ./mpmtr

# Install the binaries and the man pages (English and Russian) and grant the
# capabilities. Run as root, or: make build && sudo make install.
install:
	@test -x mpmtr || { echo 'run "make build" first'; exit 1; }
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/ru/man1
	install -m 0755 mpmtr mpmtr-app-http mpmtr-hop-snmp $(DESTDIR)$(BINDIR)/
	install -m 0644 $(MANPAGES:%=man/%) $(DESTDIR)$(MANDIR)/man1/
	install -m 0644 $(MANPAGES:%=man/ru/%) $(DESTDIR)$(MANDIR)/ru/man1/
	@if [ -z "$(DESTDIR)" ]; then setcap cap_net_raw,cap_net_admin+ep $(BINDIR)/mpmtr || \
		echo 'setcap failed: run "sudo setcap cap_net_raw,cap_net_admin+ep $(BINDIR)/mpmtr"'; fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/mpmtr $(DESTDIR)$(BINDIR)/mpmtr-app-http $(DESTDIR)$(BINDIR)/mpmtr-hop-snmp
	rm -f $(MANPAGES:%=$(DESTDIR)$(MANDIR)/man1/%) $(MANPAGES:%=$(DESTDIR)$(MANDIR)/ru/man1/%)

# The man pages render without warnings.
man-check:
	@for p in $(MANPAGES:%=man/%) $(MANPAGES:%=man/ru/%); do \
		out=$$(LC_ALL=C.UTF-8 MANWIDTH=80 man --warnings -E UTF-8 -l $$p 2>&1 >/dev/null); \
		test -z "$$out" || { echo "$$p:"; echo "$$out"; exit 1; }; \
	done

# The man pages as Markdown in docs/man, for reading on the web. Needs pandoc
# (the version CI pins: PANDOC_VERSION in .github/workflows/ci.yml).
man-md:
	@mkdir -p docs/man
	@for p in $(MANPAGES:.1=); do \
		{ printf '<!-- Generated from man/%s.1 by "make man-md": edit the man page, not this file. -->\n\n[Русская версия](%s.ru.md)\n\n' $$p $$p; \
		  pandoc -f man -t gfm -L man/gfm.lua man/$$p.1; } > docs/man/$$p.md || exit 1; \
		{ printf '<!-- Generated from man/ru/%s.1 by "make man-md": edit the man page, not this file. -->\n\n[English version](%s.md)\n\n' $$p $$p; \
		  pandoc -f man -t gfm -L man/gfm.lua man/ru/$$p.1; } > docs/man/$$p.ru.md || exit 1; \
	done

# Release archives for linux/amd64 and linux/arm64 in dist/.
dist:
	rm -rf dist && mkdir -p dist
	for arch in amd64 arm64; do \
		d=dist/mpmtr-$(VERSION)-linux-$$arch; mkdir -p $$d/man/ru; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $$d/mpmtr . && \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $$d/mpmtr-app-http ./cmd/mpmtr-app-http && \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $$d/mpmtr-hop-snmp ./cmd/mpmtr-hop-snmp && \
		mkdir -p $$d/docs && cp LICENSE THIRD_PARTY_LICENSES README.md README.ru.md $$d/ && cp docs/*.md $$d/docs/ && cp -r examples $$d/ && \
		cp $(MANPAGES:%=man/%) $$d/man/ && cp $(MANPAGES:%=man/ru/%) $$d/man/ru/ && \
		tar -C dist -czf $$d.tar.gz $$(basename $$d) && rm -rf $$d || exit 1; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS

clean:
	rm -rf mpmtr mpmtr-app-http mpmtr-hop-snmp integration.test dist
