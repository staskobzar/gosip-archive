package sipmsg

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
