.PHONY: build test check ssg docs docs-check docs-serve

build:
	go build -buildvcs=false -o bin/lend ./cmd/lend

test:
	go test -race ./...

check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	go vet ./...
	go test -race ./...
	sh -n install.sh
	python3 -m unittest discover -s scripts/tests -v

ssg:
	cd docs && go run -buildvcs=false ./cmd

docs: ssg

docs-check: ssg
	@test -z "$$(gofmt -l docs/cmd)" || { gofmt -l docs/cmd; exit 1; }
	cd docs && go vet ./...
	python3 scripts/check_docs.py

docs-serve:
	cd docs && go run -buildvcs=false ./cmd -serve 127.0.0.1:3000
