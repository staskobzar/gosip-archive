package sipmsg

import (
	"bytes"
	"strings"
)

// HdrType type header ID
type HdrType int

// SIP Header identifiers
const (
	MsgEOF HdrType = iota
	SIPHdrGeneric
	SIPHdrRequestLine
	SIPHdrStatusLine
	SIPHdrAccept
	SIPHdrAcceptEncoding
	SIPHdrAcceptLanguage
	SIPHdrAlertInfo
	SIPHdrAllow
	SIPHdrAuthenticationInfo
	SIPHdrAuthorization
	SIPHdrCallID
	SIPHdrCallInfo
	SIPHdrContact
	SIPHdrContentDisposition
	SIPHdrContentEncoding
	SIPHdrContentLanguage
	SIPHdrContentLength
	SIPHdrContentType
	SIPHdrCSeq
	SIPHdrDate
	SIPHdrErrorInfo
	SIPHdrExpires
	SIPHdrFrom
	SIPHdrInReplyTo
	SIPHdrMaxForwards
	SIPHdrMIMEVersion
	SIPHdrMinExpires
	SIPHdrOrganization
	SIPHdrPriority
	SIPHdrProxyAuthenticate
	SIPHdrProxyAuthorization
	SIPHdrProxyRequire
	SIPHdrRecordRoute
	SIPHdrReplyTo
	SIPHdrRequire
	SIPHdrRetryAfter
	SIPHdrRoute
	SIPHdrServer
	SIPHdrSubject
	SIPHdrSupported
	SIPHdrTimestamp
	SIPHdrTo
	SIPHdrUnsupported
	SIPHdrUserAgent
	SIPHdrVia
	SIPHdrWarning
	SIPHdrWWWAuthenticate
)

type HeadersList []*Header

func (l HeadersList) Count() int {
	return len(l)
}

func (l HeadersList) FindByName(name string) *Header {
	for _, h := range l {
		if strings.EqualFold(name, h.Name()) {
			return h
		}
	}
	return nil
}

type Header struct {
	buf   []byte
	id    HdrType
	name  pl
	value pl
}

func (h *Header) ID() HdrType {
	return h.id
}

func (h *Header) Name() string {
	return string(h.buf[h.name.p:h.name.l])
}

func (h *Header) Value() string {
	return string(h.buf[h.value.p:h.value.l])
}

type CSeq struct {
	Num    uint
	Method string
}

func searchParam(name string, buf []byte, params []pl) (string, bool) {
	for _, p := range params {
		prm := bytes.SplitN(buf[p.p:p.l], []byte("="), 2)
		if bytes.EqualFold([]byte(name), prm[0]) {
			if len(prm) < 2 {
				return "", true
			}
			return string(prm[1]), true
		}
	}
	return "", false
}
