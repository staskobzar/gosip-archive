package sipmsg

import "fmt"

type gosipError struct {
	s string
}

func errorNew(ctx string) *gosipError {
	return &gosipError{ctx}
}

func (e *gosipError) msg(msg string, args ...interface{}) *gosipError {
	txt := fmt.Sprintf(msg, args...)
	e.s = e.s + ": " + txt
	return e
}

func (e *gosipError) Error() string {
	return e.s
}
