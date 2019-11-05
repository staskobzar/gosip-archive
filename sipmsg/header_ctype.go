package sipmsg

import "bytes"

// ContentType structure represents SIP body type description
type ContentType struct {
	mtype    []byte
	msubtype []byte
	params   map[string][]byte
}

// MediaType content type media type
func (ct *ContentType) MediaType() string {
	return string(ct.mtype)
}

// MediaSubtype content type media sub-type
func (ct *ContentType) MediaSubtype() string {
	return string(ct.msubtype)
}

// IsSDP returns true if content type is application/sdp
func (ct *ContentType) IsSDP() bool {
	return bytes.EqualFold([]byte("application"), ct.mtype) &&
		bytes.EqualFold([]byte("sdp"), ct.msubtype)
}

// Param content type header parameter
func (ct *ContentType) Param(name string) string {
	val, ok := ct.params[name]
	if !ok {
		return ""
	}
	return string(val)
}
