package sdp

import "fmt"

type sdpError struct {
	s string
	e string
}

func errorNew(ctx string) *sdpError {
	return &sdpError{s: ctx}
}

func (e *sdpError) msg(msg string, args ...interface{}) *sdpError {
	txt := fmt.Sprintf(msg, args...)
	e.e = ": " + txt
	return e
}

func (e *sdpError) Error() string {
	return e.s + e.e
}
