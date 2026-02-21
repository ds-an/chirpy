.DEFAULT_GOAL := build-server

.PHONY: build-server goose-up goose-down sqlc-generate

build-server:
	go build -o out && ./out

goose-up:
	cd sql/schema/ && goose postgres postgres://postgres:postgres@localhost:5432/chirpy up && cd -

goose-down:
	cd sql/schema/ && goose postgres postgres://postgres:postgres@localhost:5432/chirpy down && cd -

sqlc-generate:
	sqlc generate

# fmt:
# 	go fmt ./...
# vet: fmt
# 	go vet ./...
# build: vet
# 	go build
#
# test:
# 	go test ./...
