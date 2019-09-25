package sipmsg

import "fmt"

type gosipError struct {
	s string
	e string
}

func errorNew(ctx string) *gosipError {
	return &gosipError{s: ctx}
}

func (e *gosipError) msg(msg string, args ...interface{}) *gosipError {
	txt := fmt.Sprintf(msg, args...)
	e.e = ": " + txt
	return e
}

func (e *gosipError) Error() string {
	return e.s + e.e
}
