.PHONY: build test install clean

build:
	go build -o bin/leakhound main.go

test:
	go test -cover -v ./...

install:
	go install

clean:
	rm -rf bin/

all: build plugin

example: build
	./bin/leakhound ./testdata/...