# Go package staskobzar/gosip/sip
# SIP message (rfc3261) parser and builder
#

.PHONY: clean

test: uri.go
	go test	-race -cover

uri.go: uri.rl
	ragel -Z -o $@ $<

# clean go tests cache
clean:
	go clean
