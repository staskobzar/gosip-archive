package sipmsg

import (
	"bytes"
	"crypto/md5"
	"fmt"
)

type AlgoType uint
type QOPType uint

const (
	QOPAuth     QOPType  = 1
	QOPAuthInt  QOPType  = 2
	QOPAuthAll  QOPType  = QOPAuth | QOPAuthInt
	AlgoMD5     AlgoType = 100
	AlgoMD5sess AlgoType = 200
)

// Challenge sturcture represents HTTP auth challenge
type Challenge struct {
	realm  []byte
	domain []byte
	nonce  []byte
	opaque []byte
	stale  bool
	algo   AlgoType
	qop    QOPType
}

// Realm return challenge realm as string
func (ch *Challenge) Realm() string { return string(ch.realm) }

// Domain return challenge domain as string
func (ch *Challenge) Domain() string { return string(ch.domain) }

// QOP return challenge qop as string. If algo is a list,
// then bitwise sum of algos is returned
func (ch *Challenge) QOP() QOPType { return ch.qop }

// IsQOPAuth returns true if qop has auth
func (ch *Challenge) IsQOPAuth() bool { return (ch.qop & QOPAuth) == QOPAuth }

// IsQOPAuthInt returns true if qop has auth-int
func (ch *Challenge) IsQOPAuthInt() bool { return (ch.qop & QOPAuthInt) == QOPAuthInt }

// Nonce return challenge nonce as string
func (ch *Challenge) Nonce() string { return string(ch.nonce) }

// Opaque return challenge opaque as string
func (ch *Challenge) Opaque() string { return string(ch.opaque) }

// Stale return challenge stale boolean
func (ch *Challenge) Stale() bool { return ch.stale }

// Algo return challenge algo as string
func (ch *Challenge) Algo() AlgoType { return ch.algo }

// Authorize creates credentials struct from challenge
func (ch *Challenge) Authorize(method, uri, user, password string) *Credentials {
	cr := &Credentials{
		username: []byte(user),
		uri:      []byte(uri),
		realm:    ch.realm,
		nonce:    ch.nonce,
		algo:     AlgoMD5,
		qop:      QOPAuth,
	}

	// HA1 = MD5(username:realm:password)
	var b1 bytes.Buffer
	b1.WriteString(user)
	b1.WriteByte(':')
	b1.Write(ch.realm)
	b1.WriteByte(':')
	b1.WriteString(password)
	h1 := fmt.Sprintf("%x", md5.Sum(b1.Bytes()))

	// HA2 = MD5(method:digestURI)
	var b2 bytes.Buffer
	b2.WriteString(method)
	b2.WriteByte(':')
	b2.WriteString(uri)
	h2 := fmt.Sprintf("%x", md5.Sum(b2.Bytes()))

	// response = MD5(HA1:nonce:HA2)
	var b3 bytes.Buffer
	b3.WriteString(h1)
	b3.WriteByte(':')
	b3.Write(ch.nonce)
	b3.WriteByte(':')
	b3.WriteString(h2)
	res := fmt.Sprintf("%x", md5.Sum(b3.Bytes()))
	cr.response = []byte(res)

	return cr
}

// Credentials sturcture represents HTTP auth credentials
type Credentials struct {
	username []byte
	realm    []byte
	nonce    []byte
	uri      []byte
	response []byte
	algo     AlgoType
	cnonce   []byte
	opaque   []byte
	qop      QOPType
	nc       uint // nonce count
}

// String returns credentials header structure as string
func (cr *Credentials) String() string {
	var buf bytes.Buffer
	buf.WriteString("Digest ")
	buf.WriteString("username=\"")
	buf.Write(cr.username)
	buf.WriteString("\", ")

	buf.WriteString("realm=\"")
	buf.Write(cr.realm)
	buf.WriteString("\", ")

	buf.WriteString("nonce=\"")
	buf.Write(cr.nonce)
	buf.WriteString("\", ")

	buf.WriteString("uri=\"")
	buf.Write(cr.uri)
	buf.WriteString("\", ")

	buf.WriteString("response=\"")
	buf.Write(cr.response)
	buf.WriteString("\", ")

	buf.WriteString("algorithm=MD5, qop=auth")

	return buf.String()
}

// Username return credentials username as string
func (cr *Credentials) Username() string { return string(cr.username) }

// Realm return credentials realm as string
func (cr *Credentials) Realm() string { return string(cr.realm) }

// Nonce return credentials nonce as string
func (cr *Credentials) Nonce() string { return string(cr.nonce) }

// CNonce return credentials cnonce as string
func (cr *Credentials) CNonce() string { return string(cr.cnonce) }

// Response return credentials response as string
func (cr *Credentials) Response() string { return string(cr.response) }

// Opaque return credentials opaque value as string
func (cr *Credentials) Opaque() string { return string(cr.opaque) }

// QOP return credentials qop (quality of protection) value as string
func (cr *Credentials) QOP() QOPType { return cr.qop }

// Algo return credentials algo as string
func (cr *Credentials) Algo() AlgoType { return cr.algo }

// URI return credentials uri as string
func (cr *Credentials) URI() string { return string(cr.uri) }

// NonceCount return credentials nonce count
func (cr *Credentials) NonceCount() int { return int(cr.nc) }
