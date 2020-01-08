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

	timer := initTimer(0)
	client := &Client{
		request:  tm.Msg,
		addr:     tm.Addr,
		mux:      &sync.Mutex{},
		chTU:     tu,
		chTransp: transp,
	}
	if client.request.IsInvite() {
		client.invite(timer)
	} else {
		client.nonInvite(timer)
	}

	return client, nil
}

func (cl *Client) invite(timer *Timer) {
	ctx, cancel := context.WithCancel(context.Background())
	cl.cancel = cancel

	cl.calling(ctx, timer)
	cl.timerB(ctx, timer)
}

func (cl *Client) calling(ctx context.Context, timer *Timer) {
	fmt.Println("send req")
	cl.state = Calling
	go func() {
		for {
			cl.chTransp <- &Message{cl.request, cl.addr}
			select {
			case <-ctx.Done():
				fmt.Println("calling expired")
				return
			case <-timer.nextA():
				if cl.state != Calling {
					return
				}
				fmt.Println("re-transmit A:", timer.A)
			}
		}
	}()
}

func (cl *Client) timerB(ctx context.Context, timer *Timer) {
	start := time.Now()
	go func() {
		select {
		case <-ctx.Done():
		case <-timer.fireB():
			cl.cancel()
			if toutResp, err := cl.request.NewResponse(408, "Request Timeout"); err == nil {
				cl.chTU <- &Message{toutResp, nil}
			}
		}
		cl.state = Terminated
		t := time.Now()
		fmt.Println("timer B fired after ", t.Sub(start))
	}()
}

func (cl *Client) nonInvite(timer *Timer) {
}
