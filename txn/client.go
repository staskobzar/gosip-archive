// Package txn SIP transaction RFC3261#section-17
package txn

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/staskobzar/gosip/sipmsg"
)

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

/*
Timer    Value            Section               Meaning
----------------------------------------------------------------------
T1       500ms default    Section 17.1.1.1     RTT Estimate
T2       4s               Section 17.1.2.2     The maximum retransmit
                                               interval for non-INVITE
                                               requests and INVITE
                                               responses
T4       5s               Section 17.1.2.2     Maximum duration a
                                               message will
                                               remain in the network
Timer A  initially T1     Section 17.1.1.2     INVITE request retransmit
                                               interval, for UDP only
Timer B  64*T1            Section 17.1.1.2     INVITE transaction
                                               timeout timer
Timer C  > 3min           Section 16.6         proxy INVITE transaction
                           bullet 11            timeout
Timer D  > 32s for UDP    Section 17.1.1.2     Wait time for response
         0s for TCP/SCTP                       retransmits
Timer E  initially T1     Section 17.1.2.2     non-INVITE request
                                               retransmit interval,
                                               UDP only
Timer F  64*T1            Section 17.1.2.2     non-INVITE transaction
                                               timeout timer
Timer G  initially T1     Section 17.2.1       INVITE response
                                               retransmit interval
Timer H  64*T1            Section 17.2.1       Wait time for
                                               ACK receipt
Timer I  T4 for UDP       Section 17.2.1       Wait time for
         0s for TCP/SCTP                       ACK retransmits
Timer J  64*T1 for UDP    Section 17.2.2       Wait time for
         0s for TCP/SCTP                       non-INVITE request
                                               retransmits
Timer K  T4 for UDP       Section 17.1.2.2     Wait time for
         0s for TCP/SCTP                       response retransmits
*/
type Timer struct {
	T1 time.Duration
	T2 time.Duration
	T4 time.Duration
	A  time.Duration
	B  time.Duration
	C  time.Duration
	D  time.Duration
	E  time.Duration
	F  time.Duration
	G  time.Duration
	H  time.Duration
	I  time.Duration
	J  time.Duration
	K  time.Duration
}

// Client trunsaction structure (RFC3261#17.1)
type Client struct {
	state   State
	request *sipmsg.Message
	addr    net.Addr
	transp  string // udp, tcp, tls ...
	ctx     context.Context
	mux     sync.Mutex
}

func InviteClient(req *sipmsg.Message, addr net.Addr, transp *string) (*Client, error) {
	return nil, nil
}
