package sipmsg

import "bytes"

// Contact SIP contact entity
type Contact struct {
	buf    []byte
	dname  pl
	addr   pl
	params []pl
}

// Location returns SIP contact address/location
func (c *Contact) Location() string {
	return string(c.buf[c.addr.p:c.addr.l])
}

// DisplayName SIP message contact display name
func (c *Contact) DisplayName() string {
	return string(bytes.TrimSpace(c.buf[c.dname.p:c.dname.l]))
}

// Param SIP message contact param search by name
func (c *Contact) Param(name string) (string, bool) {
	return searchParam(name, c.buf, c.params)
}

// ContactsList SIP message contacts list
type ContactsList struct {
	buf  []byte
	name pl
	cnt  []Contact
	iter int
	star bool // Contact list is *
}

// Count number of contacts in SIP message
func (cl *ContactsList) Count() int {
	return len(cl.cnt)
}

// First return first contact header of the SIP message
func (cl *ContactsList) First() *Contact {
	cl.iter = 0 // reset iteration
	if len(cl.cnt) > 0 {
		return &cl.cnt[0]
	}
	return nil
}

// Next iterate next contact header
func (cl *ContactsList) Next() *Contact {
	cl.iter++
	if cl.iter < len(cl.cnt) {
		return &cl.cnt[cl.iter]
	}
	return nil
}

// IsStar returns True if SIP contact has STAR "*"
func (cl *ContactsList) IsStar() bool {
	return cl.star
}

func (cl *ContactsList) push(cnt Contact) {
	cl.cnt = append(cl.cnt, cnt)
}
