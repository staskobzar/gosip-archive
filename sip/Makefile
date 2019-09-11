# Go package staskobzar/gosip/sip
# SIP message (rfc3261) parser and builder
#

.PHONY: clean cov

test: uri_parser.go
	go test	-race -cover

cov:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=. -benchmem

lint:
	golint uri.go

uri_parser.go: uri_parser.rl
	ragel -Z -o $@ $<

# clean go tests cache
clean:
	go clean
