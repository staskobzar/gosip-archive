package txn

import (
	"sync"
	"testing"
	"time"

	"github.com/staskobzar/gosip/sipmsg"
	"github.com/staskobzar/gosip/transp"
	"github.com/stretchr/testify/assert"
)

func initInvite() *sipmsg.Message {
	from := sipmsg.NewHdrFrom("Bob Smith", "sip:bob@voip.com", nil)
	to := sipmsg.NewHdrTo("", "sip:alice@voip.com", nil)

	msg, err := sipmsg.NewRequest("INVITE", "sip:alice@atlanta.com", nil, to, from, 102, 70)
	if err != nil {
		return nil
	}
	return msg
}

func TestTxnClientInvalidReq(t *testing.T) {
	txn, err := NewClient(&Message{nil, transp.UDPAddr("192.168.0.1:5060")}, nil, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid sip message")
	assert.Nil(t, txn)

	msg := initInvite()
	txn, err = NewClient(&Message{msg, nil}, nil, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid transport address")
	assert.Nil(t, txn)

	resp, _ := msg.NewResponse(100, "Trying")
	txn, err = NewClient(&Message{resp, transp.UDPAddr("10.0.0.1:5060")}, nil, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sip request expected")
	assert.Nil(t, txn)
}

func TestTxnInvClientStateCallingRetrans(t *testing.T) {
	cl := &Client{
		request:  initInvite(),
		addr:     transp.UDPAddr("10.0.0.1:5060"),
		mux:      &sync.Mutex{},
		chTU:     make(chan *Message),
		chTransp: make(chan *Message),
		timer:    initTimer(5 * time.Millisecond),
	}
	cl.invite()

	var retrans int
	var respCode string
	var timeout bool
Loop:
	for {
		select {
		case <-time.After(1000 * time.Millisecond):
			timeout = true
			break Loop
		case tm := <-cl.chTU:
			respCode = tm.Msg.StatusLine.Code()
			break Loop
		case <-cl.chTransp:
			retrans += 1
		}
	}
	assert.False(t, timeout)
	assert.Equal(t, "408", respCode)
	assert.Equal(t, 6, retrans)
}

func TestTxnInvClientStateCalling2XXResp(t *testing.T) {
	msg := initInvite()
	cl := &Client{
		request:  msg,
		addr:     transp.UDPAddr("10.0.0.1:5060"),
		mux:      &sync.Mutex{},
		chTU:     make(chan *Message),
		chTransp: make(chan *Message),
		timer:    initTimer(0),
	}
	cl.invite()
	resp, err := msg.NewResponse(200, "OK")
	assert.Nil(t, err)
	resp.AddToTag()
	cl.Recv(&Message{resp, cl.addr})
	tm := <-cl.chTU
	assert.Equal(t, "200", tm.Msg.StatusLine.Code())
	assert.True(t, cl.IsTerminated())
}
