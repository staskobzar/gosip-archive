// Package txn SIP transaction RFC3261#section-17
package txn

import (
	"context"
	"sync"

	"github.com/staskobzar/gosip/sipmsg"
	"github.com/staskobzar/gosip/transp"
)

// ErrorTxnClient transaction client error
var ErrorTxnClient = errorNew("Transaction Client")

// State of transaction state machine
type State uint8

// Client transaction states
const (
	Idle State = iota
	Calling
	Proceeding
	Completed
	Terminated
)

// Client trunsaction structure (RFC3261#17.1)
type Client struct {
	state   State
	request *sipmsg.Message
	addr    *transp.Addr
	cancel  context.CancelFunc
	mux     *sync.Mutex
}

// NewClient creates new client transaction RFC3261#17
// If method is INVITE then creates INVITE transaction,
// non-INVITE otherwise
func NewClient(req *sipmsg.Message, addr *transp.Addr) (*Client, error) {
	if req == nil {
		return nil, ErrorTxnClient.msg("invalid sip message")
	}
	if addr == nil {
		return nil, ErrorTxnClient.msg("invalid transport address")
	}
	if !req.IsRequest() {
		return nil, ErrorTxnClient.msg("sip request expected")
	}

	if req.IsInvite() {
		return invClient(req, addr)
	}

	return nonInvClient(req, addr)
}

func invClient(req *sipmsg.Message, addr *transp.Addr) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := &Client{
		state:   Calling,
		request: req,
		addr:    addr,
		cancel:  cancel,
		mux:     &sync.Mutex{},
	}
	return cl, nil
}

func nonInvClient(req *sipmsg.Message, addr *transp.Addr) (*Client, error) {
	return nil, nil
}
