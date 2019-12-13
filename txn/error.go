package txn

import "fmt"

type txnError struct {
	s string
	e string
}

func errorNew(ctx string) *txnError {
	return &txnError{s: ctx}
}

func (e *txnError) msg(msg string, args ...interface{}) *txnError {
	txt := fmt.Sprintf(msg, args...)
	e.e = ": " + txt
	return e
}

func (e *txnError) Error() string {
	return e.s + e.e
}
