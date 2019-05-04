all: test

test:
	golint ./...
	go vet ./...
	go test -coverprofile=coverage.out ./...

coverage: test
	go tool cover -html coverage.out
	
.PHONY: test coverage
