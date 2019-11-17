# Go package staskobzar/gosip/sip
# SDP message (rfc4566) parser and builder
#

test: parser.go
	go fmt
	go test	-race -cover

cov:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=. -benchmem

lint:
	golint builder*.go message*.go

fuzz:
	go-fuzz-build
	go-fuzz -bin=sdp-fuzz.zip -workdir=fuzz

%.go: %.rl
	ragel -Z -o $@ $<

# clean go tests cache
clean:
	go clean
