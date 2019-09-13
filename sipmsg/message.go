package sipmsg

type ptr uint16

// Structure to replresent position in []byte buffer
// "p" points to start position and "l" points to the last.
// That helps to avoid additional memory allocations.
type pl struct {
	p ptr
	l ptr
}
