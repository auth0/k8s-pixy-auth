
SOURCEDIR=.
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
PACKAGE_PATH=$(shell go list -m)

COMMIT_SHA=$(shell git rev-parse HEAD)
VERSION_TAG=$(shell git describe --abbrev=0 --tags)
DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

LDFLAGS=-ldflags '-s -w -X $(PACKAGE_PATH)/cmd.commitSHA=$(COMMIT_SHA) -X $(PACKAGE_PATH)/cmd.version=$(VERSION_TAG) -X $(PACKAGE_PATH)/cmd.buildDate=$(DATE)'

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
	go test -v -cover -race -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

.PHONY: coveralls
coveralls: cover
	go get golang.org/x/tools/cmd/cover
	go get github.com/mattn/goveralls
	go test -v -covermode=count -coverprofile=coverage.out
	goveralls -coverprofile=cover.out -service=travis-ci -repotoken=$(COVERALLS_TOKEN)

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
	go get golang.org/x/lint/golint@v0.0.0-20190409202823-959b441ac422
	go get github.com/onsi/ginkgo/ginkgo@v1.8.0
	go get gotest.tools/gotestsum@v0.3.4

.PHONY: install-modules
install-modules:
	go mod download

.PHONY: echo-version
echo-version:
	@echo $(VERSION_TAG)

.PHONY: package
package:
	./scripts/package.sh
