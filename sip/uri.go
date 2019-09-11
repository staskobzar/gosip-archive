package sip

// URI holds SIP(s) uri structure
type URI struct {
	scheme   string
	user     string
	password string
	host     string
	port     string
}

func (u *URI) Scheme() string   { return u.scheme }
func (u *URI) User() string     { return u.user }
func (u *URI) Password() string { return u.password }
func (u *URI) Host() string     { return u.host }
func (u *URI) Port() string     { return u.port }
