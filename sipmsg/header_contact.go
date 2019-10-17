package sipmsg

import (
	"strings"
)

// Contact SIP contact entity
type Contact struct {
	buf    buffer
	name   pl
	dname  pl
	addr   pl
	params []pl
}

// NewHdrContact creates new Contact SIP header
func NewHdrContact(dname, addr string, params map[string]string) *Contact {
	c := &Contact{buf: buffer{}}

	c.buf.name("Contact", &c.name)
	if len(dname) > 0 {
		c.buf.wwrap(`""`, strings.ReplaceAll(dname, "\"", "%22"), &c.dname, false)
		c.buf.WriteByte(' ')
	}

	c.buf.wwrap("<>", addr, &c.addr, true)

	for name, val := range params {
		c.params = append(c.params, c.buf.param(name, val))
	}

	c.buf.crlf()
	return c
}

// Location returns SIP contact address/location
func (c *Contact) Location() string {
	return c.buf.str(c.addr)
}

// DisplayName SIP message contact display name
func (c *Contact) DisplayName() string {
	return strings.TrimSpace(c.buf.str(c.dname))
}

// Param SIP message contact param search by name
func (c *Contact) Param(name string) (string, bool) {
	return searchParam(name, c.buf.Bytes(), c.params)
}

// ContactsList SIP message contacts list
type ContactsList struct {
	cnt  []*Contact
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
	return cl.cnt[0]
}

// Next iterate next contact header
func (cl *ContactsList) Next() *Contact {
	cl.iter++
	if cl.iter < len(cl.cnt) {
		return cl.cnt[cl.iter]
	}
	return nil
}

// IsStar returns True if SIP contact has STAR "*"
func (cl *ContactsList) IsStar() bool {
	return cl.star
}
