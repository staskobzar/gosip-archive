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
	buf    []byte
	fname  pl
	dname  pl
	addr   pl
	params []pl
}

// Addr Route address
func (r *Route) Addr() string {
	return string(r.buf[r.addr.p:r.addr.l])
}

// AddrURI returns Route address URI structure
func (r *Route) AddrURI() *URI {
	return URIParse(r.buf[r.addr.p:r.addr.l])
}

// Param returns true if Route parameter exists and parameter value
func (r *Route) Param(name string) (string, bool) {
	return searchParam(name, r.buf, r.params)
}
