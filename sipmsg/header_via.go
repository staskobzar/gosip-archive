package sipmsg

type ViaList struct {
	buf  []byte
	name pl
	vias []Via
}

type Via struct {
	buf    []byte
	trans  pl // transport
	host   pl
	port   pl
	branch pl
	ttl    pl
	maddr  pl
	recevd pl
}
