# Go package staskobzar/gosip/tnx
# SIP third layer: Transactions
# RFC3261#section-17
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

# clean go tests cache
clean:
	go clean
