package txn

import "time"

// Timer struction for transactions. RFC3261#Table 4: Summary of timers
type Timer struct {
	// T1 500ms; default RTT Estimate
	T1 time.Duration
	// T2 4s;  The maximum retransmit interval for non-INVITE requests and INVITE responses
	T2 time.Duration
	// T4 5s; Maximum duration a message will remain in the network
	T4 time.Duration
	// A timer initially T1; INVITE request retransmit interval, for UDP only
	A time.Duration
	// B timer 64*T1 INVITE transaction timeout timer
	B time.Duration
	// C timer > 3min; proxy INVITE transaction timeout
	C time.Duration
	// D timer > 32s for UDP, 0s for TCP/SCTP; Wait time for response retransmits
	D time.Duration
	// E timer initially T1; non-INVITE request retransmit interval, UDP only
	E time.Duration
	// F timer 64*T1; non-INVITE transaction timeout timer
	F time.Duration
	// G timer initially T1; INVITE response retransmit interval
	G time.Duration
	// H timer H  64*T1; Wait time for ACK receipt
	H time.Duration
	// I timer T4 for UDP 0s for TCP/SCTP; Wait time for ACK retransmits
	I time.Duration
	// J timer 64*T1 for UDP 0s for TCP/SCTP; Wait time for non-INVITE request retransmits
	J time.Duration
	// K timer T4 for UDP 0s for TCP/SCTP; Wait time for response retransmits
	K time.Duration
}

func initTimer(t1 time.Duration) *Timer {
	t := &Timer{}

	// T1 500ms; default RTT Estimate
	if t1 > 0 {
		t.T1 = t1
	} else {
		t.T1 = 500 * time.Millisecond
	}

	// T2 4s;  The maximum retransmit interval for non-INVITE requests and INVITE responses
	t.T2 = 4 * time.Second
	// T4 5s; Maximum duration a message will remain in the network
	t.T4 = 5 * time.Second
	// A timer initially T1; INVITE request retransmit interval, for UDP only
	t.A = t.T1
	// B timer 64*T1 INVITE transaction timeout timer
	t.B = 64 * t.T1
	// C timer > 3min; proxy INVITE transaction timeout
	// TODO: update later to correct value or document here
	t.C = 0
	// D timer > 32s for UDP, 0s for TCP/SCTP; Wait time for response retransmits
	// TODO: update later to correct value or document here
	t.D = 0
	// E timer initially T1; non-INVITE request retransmit interval, UDP only
	t.E = t.T1
	// F timer 64*T1; non-INVITE transaction timeout timer
	t.F = 64 * t.T1
	// G timer initially T1; INVITE response retransmit interval
	t.G = t.T1
	// H timer H  64*T1; Wait time for ACK receipt
	t.H = 64 * t.T1
	// I timer T4 for UDP 0s for TCP/SCTP; Wait time for ACK retransmits
	// TODO: update later to correct value or document here
	t.I = 0
	// J timer 64*T1 for UDP 0s for TCP/SCTP; Wait time for non-INVITE request retransmits
	// TODO: update later to correct value or document here
	t.J = 64 * t.T1
	// K timer T4 for UDP 0s for TCP/SCTP; Wait time for response retransmits
	// TODO: update later to correct value or document here
	t.K = t.T4

	return t
}

func (t *Timer) nextA() <-chan struct{} {
	t.A = t.A * 2
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		<-time.After(t.A)
	}()
	return ch
}

func (t *Timer) fireB() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		<-time.After(t.B)
	}()
	return ch
}
