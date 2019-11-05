# Go package staskobzar/gosip/sip
# SIP message (rfc3261) parser and builder
#

.PHONY: clean cov test fuzz

test: parser_uri.go parser_msg.go parser_challenge.go parser_cred.go parser_ctype.go
	go fmt
	go test	-race -cover

cov:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=. -benchmem

lint:
	golint $(filter-out $(wildcard *_parser.go),$(wildcard *.go))

fuzz:
	go-fuzz-build
	go-fuzz -bin=sipmsg-fuzz.zip -workdir=fuzz

%.go: %.rl
	ragel -Z -o $@ $<

# clean go tests cache
clean:
	go clean
