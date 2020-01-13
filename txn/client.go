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

// Message transaction message structure
type Message struct {
	// Msg SIP message structure from sipmsg module
	Msg *sipmsg.Message
	// Addr destination address
	Addr *transp.Addr
}

// Client trunsaction structure (RFC3261#17.1)
type Client struct {
	state    State
	request  *sipmsg.Message
	response *sipmsg.Message
	addr     *transp.Addr
	cancel   context.CancelFunc
	timer    *Timer
	mux      *sync.Mutex
	chTU     chan *Message
	chTransp chan *Message
}

// NewClient creates new client transaction RFC3261#17
// If method is INVITE then creates INVITE transaction,
// non-INVITE otherwise
func NewClient(tm *Message, tu chan *Message, transp chan *Message) (*Client, error) {

	if tm.Msg == nil {
		return nil, ErrorTxnClient.msg("invalid sip message")
	}
	if tm.Addr == nil {
		return nil, ErrorTxnClient.msg("invalid transport address")
	}
	if !tm.Msg.IsRequest() {
		return nil, ErrorTxnClient.msg("sip request expected")
	}

	client := &Client{
		request:  tm.Msg,
		addr:     tm.Addr,
		mux:      &sync.Mutex{},
		timer:    initTimer(0),
		chTU:     tu,
		chTransp: transp,
	}
	if client.request.IsInvite() {
		client.invite()
	} else {
		client.nonInvite()
	}

	return client, nil
}

// Recv update client transaction with new SIP message
func (cl *Client) Recv(tm *Message) error {
	if tm.Msg == nil {
		return ErrorTxnClient.msg("invalid sip message")
	}
	if tm.Msg.IsRequest() {
		return ErrorTxnClient.msg("sip response expected")
	}
	switch cl.state {
	case Calling:
		cl.smInvCalling(tm)
	}
	return nil
}

func (cl *Client) smInvCalling(tm *Message) {
	go func() {
		switch code := tm.Msg.Code(); {
		case code >= 200 && code < 300:
			cl.terminate()
			cl.chTU <- tm
		case code >= 100 && code < 200:
			cl.chTU <- tm
			cl.state = Proceeding
		case code >= 300 && code <= 699:
			// send ACK
			ack, _ := cl.request.NewACK(tm.Msg)
			cl.chTransp <- &Message{ack, cl.addr}
			cl.chTU <- tm
			// completed
		}
	}()
}

// IsTerminated returns true if Client state is Terminated
func (cl *Client) IsTerminated() bool {
	return cl.state == Terminated
}

func (cl *Client) invite() {
	ctx, cancel := context.WithCancel(context.Background())
	cl.cancel = cancel

	cl.calling(ctx)
	cl.timerB(ctx)
}

func (cl *Client) calling(ctx context.Context) {
	cl.state = Calling
	go func() {
		for {
			cl.chTransp <- &Message{cl.request, cl.addr}
			select {
			case <-ctx.Done():
				return
			case <-cl.timer.nextA():
				if cl.state != Calling {
					return
				}
			}
		}
	}()
}

func (cl *Client) timerB(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
		case <-cl.timer.fireB():
			cl.terminate()
			if toutResp, err := cl.request.NewResponse(408, "Request Timeout"); err == nil {
				cl.chTU <- &Message{toutResp, nil}
			}
		}
	}()
}

func (cl *Client) terminate() {
	cl.cancel()
	cl.state = Terminated
}

func (cl *Client) nonInvite() {
}
