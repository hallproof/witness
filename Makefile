.PHONY: test vet lint tidy check

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

check: vet lint test
