export GOPRIVATE := code.cfops.it
IMPORT_PATH := github.com/majek/slirpnetstack
GOFLAGS=-ldflags=-compressdwarf=false

bin/slirpnetstack: *.go go.mod
	go build \
		$(GOFLAGS) \
		-o $@ \
		$(IMPORT_PATH)


bin/slirpnetstack.cover: *.go go.mod
	go test \
		$(GOFLAGS) \
		-coverpkg="$(IMPORT_PATH)" \
		-c \
		-o $@ \
		-tags testrunmain \
		$(IMPORT_PATH)

bin/gocovmerge:
	go build -o $@ github.com/wadey/gocovmerge

.PHONY: format
format:
	go fmt *go

ifdef COVER
PWD:=$(CURDIR)
SLIRPNETSTACKDEP:=./bin/slirpnetstack.cover
SLIRPNETSTACKBIN:= "./bin/slirpnetstack.cover -test.coverprofile=$(PWD)/.cover/%(nr)s.out"
else
SLIRPNETSTACKDEP:=./bin/slirpnetstack
SLIRPNETSTACKBIN:= "./bin/slirpnetstack"
endif

.PHONY: test
test: $(SLIRPNETSTACKDEP)
	SLIRPNETSTACKBIN=$(SLIRPNETSTACKBIN) \
	PYTHONPATH=. \
	PYTHONIOENCODING=utf-8 \
		unshare -Ur python3 -m tests.runner tests

cover: bin/gocovmerge
	@-mkdir -p .cover
	@rm -f .cover/*.out .cover/all.merged
	@$(MAKE) test COVER=1
	@./bin/gocovmerge .cover/*.out > .cover/all.merged
	@echo "[*] Total test coverage:"
	@./tests/cover.py .cover/all.merged
ifdef CI
	go tool cover -html .cover/all.merged -o .cover/all.html
endif
ifdef HTML
	go tool cover -html .cover/all.merged
endif

clean:
	rm -f bin/* .cover/*out

GOTESTTARGETS = \
	bin/mocktcpecho \
	bin/mockudpecho \
	bin/mockdns

test: $(GOTESTTARGETS)
$(GOTESTTARGETS): $(wildcard tests/*/*.go)
	go build -o $@ $(IMPORT_PATH)/tests/$(subst bin/,,$@)

update-gomod:
	# was:
	# go get -u gvisor.dev/gvisor@go all
	# but we have regression in "Don't support address ranges" commit
	go get -u gvisor.dev/gvisor@2f6429be86f927058392a85dcb6512bebb836d9d
	go mod tidy
	$(MAKE) bin/gocovmerge bin/slirpnetstack bin/slirpnetstack.cover
