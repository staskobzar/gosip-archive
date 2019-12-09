// Package txn SIP transaction RFC3261#section-17
package txn

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
}
