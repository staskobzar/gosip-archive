package txn

import (
	"fmt"
	"sync"
	"testing"

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

func TestTxnInitInviteClient(t *testing.T) {
	msg := initInvite()
	addr := transp.UDPAddr("10.0.0.1:5060")
	timer := initTimer(0) //10 * time.Millisecond)
	chtu := make(chan *Message)
	chtr := make(chan *Message)
	cl := &Client{
		request:  msg,
		addr:     addr,
		mux:      &sync.Mutex{},
		chTU:     chtu,
		chTransp: chtr,
	}
	cl.invite(timer)
Loop:
	for {
		select {
		case tm := <-cl.chTU:
			fmt.Println(tm.Msg.String())
			break Loop
		case tm := <-cl.chTransp:
			fmt.Println(tm.Msg.String())
		}
	}
	fmt.Println("DONE")
}
