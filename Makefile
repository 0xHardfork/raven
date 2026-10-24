.PHONY: all build test clean run package docker-build docker-up docker-down

BINARY_NAME=raven
BUILD_DIR=bin
VERSION?=v1.0.0

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-w -s" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/raven

test:
	go test -v ./...

clean:
	rm -rf $(BUILD_DIR) dist

package:
	bash scripts/package.sh $(VERSION)

docker-build:
	docker build -t raven:$(VERSION) -t raven:latest .

docker-up:
	docker compose -f docker-compose.prod.yaml up -d

docker-down:
	docker compose -f docker-compose.prod.yaml down
