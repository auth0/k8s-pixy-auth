
SOURCEDIR=.
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
PACKAGE_PATH=$(shell go list -m)

COMMIT_SHA=$(shell git rev-parse HEAD)
VERSION_TAG=$(shell git describe --abbrev=0 --tags)
DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

LDFLAGS=-ldflags "-X $(PACKAGE_PATH)/cmd.commitSHA=$(COMMIT_SHA) -X $(PACKAGE_PATH)/cmd.version=$(VERSION_TAG) -X $(PACKAGE_PATH)/cmd.buildDate=$(DATE)"

BINARY=k8s-pixy-auth

.DEFAULT_GOAL: $(BINARY)

$(BINARY): $(SOURCES)
	BUILD_OUTPUT=$(BINARY) $(MAKE) base-build

.PHONY: lint
lint:
	@go vet $(PACKAGE_PATH)
	@golint ./...

.PHONY: test
test:
	@mkdir -p test-results/junit
	go test -count=1 ./... # use count=1 to force not using the test cache

.PHONY: test-watch
test-watch:
	@ginkgo watch ./...

.PHONY: cover
cover:
	go test -v -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

.PHONY: fmt
fmt:
	@gofmt -e -s -l -w $(shell find . -name "*.go")

.PHONY: base-build
base-build:
	go build -o $(BUILD_OUTPUT) $(LDFLAGS) .

.PHONY: build-linux
build-linux:
	GOOS=linux BUILD_OUTPUT=binaries/linux/$(BINARY) $(MAKE) base-build

.PHONY: build-windows
build-windows:
	GOOS=windows BUILD_OUTPUT=binaries/windows/$(BINARY).exe $(MAKE) base-build

.PHONY: build-darwin
build-darwin:
	GOOS=darwin BUILD_OUTPUT=binaries/darwin/$(BINARY) $(MAKE) base-build

.PHONY: build-all-platforms
build-all-platforms: build-linux build-windows build-darwin

.PHONY: install-tools
install-tools:
	go get -u golang.org/x/lint/golint
	go get -u github.com/onsi/ginkgo/ginkgo
	go get -u gotest.tools/gotestsum

.PHONY: echo-version
echo-version:
	@echo $(VERSION_TAG)
