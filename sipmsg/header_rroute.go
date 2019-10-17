package sipmsg

// Recorde and Record-Route headers structure

// RouteList list of Route/Record-Route header
type RouteList []*Route

// Count number of Route (Record-Route) headers
func (r RouteList) Count() int {
	return len(r)
}

// Route headers Route/Record-Route structure
type Route struct {
	buf    buffer
	fname  pl
	dname  pl
	addr   pl
	params []pl
}

// NewHdrRoute creates Route header with one address
func NewHdrRoute(addr string) *Route {
	return newRRoute("Route", addr)
}

// NewHdrRecordRoute creates Record-Route header with one address
func NewHdrRecordRoute(addr string) *Route {
	return newRRoute("Record-Route", addr)
}

func newRRoute(name, addr string) *Route {
	r := &Route{buf: buffer{}}
	r.buf.name(name, &r.fname)
	r.buf.wwrap("<>", addr, &r.addr, true)
	r.buf.crlf()
	return r
}

// Addr Route address
func (r *Route) Addr() string {
	return r.buf.str(r.addr)
}

// AddrURI returns Route address URI structure
func (r *Route) AddrURI() *URI {
	return URIParse(r.buf.byt(r.addr))
}

// Param returns true if Route parameter exists and parameter value
func (r *Route) Param(name string) (string, bool) {
	return searchParam(name, r.buf.Bytes(), r.params)
}
