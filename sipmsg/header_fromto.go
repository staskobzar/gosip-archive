package sipmsg

import (
	"bytes"
)

// HeaderFromTo SIP headers From/To structure
type HeaderFromTo struct {
	buf    []byte
	name   pl // header name
	dname  pl // display name
	addr   pl
	tag    pl
	params []pl
}

// DisplayName From/To header display name
func (h *HeaderFromTo) DisplayName() string {
	name := h.buf[h.dname.p:h.dname.l]
	return string(bytes.TrimSpace(name))
}

// Addr From/To header URI address as string
func (h *HeaderFromTo) Addr() string {
	return string(h.buf[h.addr.p:h.addr.l])
}

// Tag From/To header tag value
func (h *HeaderFromTo) Tag() string {
	return string(h.buf[h.tag.p:h.tag.l])
}

// Param header parameters
func (h *HeaderFromTo) Param(name string) (string, bool) {
	for _, p := range h.params {
		prm := bytes.SplitN(h.buf[p.p:p.l], []byte("="), 2)
		if bytes.EqualFold([]byte(name), prm[0]) {
			if len(prm) < 2 {
				return "", true
			}
			return string(prm[1]), true
		}
	}
	return "", false
}

func newHeaderFromTo(buf []byte, params []pl, fname, dname, addr, tag pl) *HeaderFromTo {
	h := &HeaderFromTo{
		buf:    buf,
		name:   fname,
		dname:  dname,
		addr:   addr,
		tag:    tag,
		params: params,
	}
	return h
}
