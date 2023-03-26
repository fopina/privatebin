SRC_PATH = "github.com/fopina/privatebin"
OUTPUT_FILE = pbin

VERSION ?= DEV

all: clean build

test:
	@go test -short ./...

race:
	@go test -race -short ./...

mem_san:
	@go test -msan -short ./...

lint:
	@golint -set_exit_status ./...

clean:
	@go clean
	@rm dist/$(OUTPUT_FILE) -f

build:
	@mkdir -p dist
	@CGO_ENABLED=0 go build -o dist/$(OUTPUT_FILE) main.go

gorelease:
	@VERSION=$(VERSION) docker run --rm --privileged \
  				-v $(PWD):/go/src/$(SRC_PATH) \
  				-v /var/run/docker.sock:/var/run/docker.sock \
  				-w /go/src/$(SRC_PATH) \
				-e VERSION \
  				goreleaser/goreleaser --skip-publish --snapshot --clean
