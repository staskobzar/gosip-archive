package sipmsg

// type header ID
type HdrType int

// SIP Header identifiers
const (
	MsgEOF HdrType = iota
	SIPHdrOther
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

type header struct {
	buf   []byte
	id    HdrType
	name  pl
	value pl
	resp  statusLine
}

type statusLine struct {
	ver    pl
	code   pl
	reason pl
}
