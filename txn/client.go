// Package txn SIP transaction RFC3261#section-17
package txn

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	chTU    chan *sipmsg.Message
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

	timer := initTimer(0)
	if req.IsInvite() {
		return invClient(req, addr, timer)
	}

	return nonInvClient(req, addr)
}

func invClient(req *sipmsg.Message, addr *transp.Addr, timer *Timer) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := &Client{
		state:   Calling,
		request: req,
		addr:    addr,
		cancel:  cancel,
		mux:     &sync.Mutex{},
	}
	cl.calling(ctx, timer)
	cl.expireB(ctx, timer)
	return cl, nil
}

func (cl *Client) calling(ctx context.Context, timer *Timer) {
	// send
	fmt.Println("send req")
	go func() {
		for {
			select {
			case <-ctx.Done():
				fmt.Println("calling expired")
				return
			case <-timer.nextA():
				if cl.state != Calling {
					return
				}
				// send
				fmt.Println("re-transmit A:", timer.A)
			}
		}
	}()
}

func (cl *Client) expireB(ctx context.Context, timer *Timer) {
	start := time.Now()
	go func() {
		select {
		case <-ctx.Done():
		case <-timer.fireB():
			cl.cancel()
		}
		cl.state = Terminated
		t := time.Now()
		fmt.Println("timer B fired after ", t.Sub(start))
	}()
}

func nonInvClient(req *sipmsg.Message, addr *transp.Addr) (*Client, error) {
	return nil, nil
}
