.PHONY: test vet lint tidy check modules

# The root module and every nested one (scripts/modules.sh). Each target runs
# in all of them.
MODULES := . $(shell scripts/modules.sh)

test:
	@set -e; for m in $(MODULES); do echo "==> $$m"; (cd $$m && go test -race ./...); done

vet:
	@set -e; for m in $(MODULES); do (cd $$m && go vet ./...); done

lint:
	@set -e; for m in $(MODULES); do echo "==> $$m"; (cd $$m && golangci-lint run ./...); done

tidy:
	@set -e; for m in $(MODULES); do (cd $$m && go mod tidy); done

check: vet lint test

modules:
	@scripts/modules.sh
