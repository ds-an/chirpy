.DEFAULT_GOAL := build-server

.PHONY: build-server

build-server:
	go build -o out && ./out

# fmt:
# 	go fmt ./...
# vet: fmt
# 	go vet ./...
# build: vet
# 	go build
#
# test:
# 	go test ./...
