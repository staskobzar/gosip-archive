package sipmsg

import (
	"bytes"
	"strings"
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

// NewHdrTo creates new To header
// First argument is display name. If display name is present then it will be
// enclosed in double quotes. Any double quotes in the display name will be escaped.
// If display name is an empty string then it will be ignored.
// uri argument will be enclosed in < and > to keep uri parameters related to the uri.
// params should have list of parameter of To header. Patameter with name "tag" is
// ignored. Tog parameter is supposed to be added with method AddTag()
// If parameter name and value are the same, then the prameter without value is added.
// For example: map[string]string{"a":"b", "c":"c"} will generate: ";a=b;c"
func NewHdrTo(dname, uri string, params map[string]string) *HeaderFromTo {
	return createHeaderFromTo("To", dname, uri, params)
}

// NewHdrFrom Creates new From header. See description of NewHdrTo for details.
func NewHdrFrom(dname, uri string, params map[string]string) *HeaderFromTo {
	return createHeaderFromTo("From", dname, uri, params)
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

// AddTag Creates tag header's parameter. Fails is tag already exists.
func (h *HeaderFromTo) AddTag() error {
	if h.tag.l > h.tag.p {
		return ErrorSIPHeader.msg("Header From/To already has Tag.")
	}
	var buf buffer
	tag := randomString()
	buf.Write(h.buf)
	buf.Truncate(buf.Len() - 2) // remove CRLF
	buf.paramVal("tag", tag, &h.tag)
	h.buf = buf.crlf()
	return nil
}

// Param header parameters
func (h *HeaderFromTo) Param(name string) (string, bool) {
	return searchParam(name, h.buf, h.params)
}

func createHeaderFromTo(name, dname, uri string, params map[string]string) *HeaderFromTo {
	var buf buffer
	h := &HeaderFromTo{}
	buf.name(name, &h.name)

	if len(dname) > 0 {
		buf.wwrap(`""`, strings.ReplaceAll(dname, "\"", "%22"), &h.dname, false)
		buf.WriteByte(' ')
	}

	buf.wwrap("<>", uri, &h.addr, true)

	for name, val := range params {
		h.params = append(h.params, buf.param(name, val))
	}

	h.buf = buf.crlf()
	return h
}

func initHeaderFromTo(buf []byte, params []pl, fname, dname, addr, tag pl) *HeaderFromTo {
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
