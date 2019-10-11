package sipmsg

import (
	"strconv"
	"strings"
)

const cookie = "z9hG4bK"

// ViaList list of via headers
type ViaList []*Via

// Count return number of Via headers
func (v ViaList) Count() int {
	return len(v)
}

// Via SIP header structure
type Via struct {
	buf    []byte
	name   pl
	trans  pl // transport
	host   pl
	port   pl
	branch pl
	ttl    pl
	maddr  pl
	recevd pl
	params pl
}

// NewHdrVia Creates new Via header
// Will generate branch parameter automatically.
// Transport must be uppercase. If port is 0 then no port set (default 5060).
// Parameters is a map. If parameters contain "branch" it will be ignored.
func NewHdrVia(trans, host string, port uint, params map[string]string) (*Via, error) {
	var buf buffer
	v := &Via{}
	buf.name("Via", &v.name)

	buf.write("SIP/2.0/", nil)
	buf.write(strings.ToUpper(trans), &v.trans)

	buf.writeBytePrefix(0x20, host, &v.host) // space + host

	if port > 65535 {
		return nil, ErrorSIPHeader.msg("Via send-by port invalid: %d", port)
	}
	if port > 0 {
		buf.writeBytePrefix(':', strconv.Itoa(int(port)), &v.port)
	}

	v.params.p = ptr(buf.Len())
	for name, val := range params {
		switch strings.ToLower(name) {
		case "ttl":
			buf.paramVal(name, val, &v.ttl)
		case "maddr":
			buf.paramVal(name, val, &v.maddr)
		case "received":
			buf.paramVal(name, val, &v.recevd)
		default:
			buf.paramVal(name, val, nil)
		}
	}
	buf.paramVal("branch", randomStringPrefix(cookie), &v.branch)
	v.params.l = buf.plen()

	v.buf = buf.crlf()
	return v, nil
}

// Transport Via header transport
func (v *Via) Transport() string {
	return string(v.buf[v.trans.p:v.trans.l])
}

// Host Via header host of send-by value
func (v *Via) Host() string {
	return string(v.buf[v.host.p:v.host.l])
}

// Port Via header port of send-by value
func (v *Via) Port() string {
	return string(v.buf[v.port.p:v.port.l])
}

// Branch Via header branch parameter
func (v *Via) Branch() string {
	return string(v.buf[v.branch.p:v.branch.l])
}

// TTL Via header time-to-live parameter
func (v *Via) TTL() string {
	return string(v.buf[v.ttl.p:v.ttl.l])
}

// MAddr Via header maddr parameter
func (v *Via) MAddr() string {
	return string(v.buf[v.maddr.p:v.maddr.l])
}

// Received Via header received parameter
func (v *Via) Received() string {
	return string(v.buf[v.recevd.p:v.recevd.l])
}
