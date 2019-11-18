# Go package staskobzar/gosip/sip
# RTP packets (RFC3550)
#

test:
	go fmt
	go test	-race -cover

cov:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=. -benchmem

lint:
	golint

#fuzz:
#	go-fuzz-build
#	go-fuzz -bin=sdp-fuzz.zip -workdir=fuzz

# clean go tests cache
clean:
	go clean
