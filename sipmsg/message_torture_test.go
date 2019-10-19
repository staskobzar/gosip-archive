package sipmsg

import (
	"testing"

	"strings"

	"github.com/stretchr/testify/assert"
)

/*
RFC 4475 SIP Torture Test Messages
SIP test messages designed to exercise and "torture" a SIP implementation.
*/

// 3.1.1.1.  A Short Tortuous INVITE
func TestMsgParseTortureWsinv(t *testing.T) {
	str := "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n" +
		"TO :\r\n sip:vivekg@chair-dnrc.example.com ;   tag    = 1918181833n\r\n" +
		`from   : "J Rosenberg \\\""       <sip:jdrosen@example.com>` +
		"\r\n  ;\r\n" +
		"  tag = 98asjd8\r\n" +
		"MaX-fOrWaRdS: 0068\r\n" +
		"Call-ID: wsinv.ndaksdj@192.0.2.1\r\n" +
		"Content-Length   : 150\r\n" +
		"cseq: 0009\r\n" +
		"  INVITE\r\n" +
		"Via  : SIP  /   2.0\r\n" +
		" /UDP\r\n 192.0.2.2;branch=390skdjuw\r\n" +
		"s :\r\n" +
		"NewFangledHeader:   newfangled value\r\n" +
		" continued newfangled value\r\n" +
		"UnknownHeaderWithUnusualValue: ;;,,;;,;\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Route:\r\n" +
		" <sip:services.example.com;lr;unknownwith=value;unknown-no-value>\r\n" +
		"v:  SIP  / 2.0  / TCP     spindle.example.com   ;\r\n" +
		"  branch  =   z9hG4bK9ikj8  ,\r\n" +
		" SIP  /    2.0   / UDP  192.168.255.111   ; branch=\r\n" +
		" z9hG4bK30239\r\n" +
		`m:"Quoted string \"\"" <sip:jdrosen@example.com> ; newparam =` +
		"\r\n      newvalue ;\r\n" +
		"  secondparam ; q = 0.33\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())
	assert.Equal(t, "sip:vivekg@chair-dnrc.example.com;unknownparam",
		msg.ReqLine.RequestURI())
	assert.Equal(t, "sip:vivekg@chair-dnrc.example.com", msg.To.Addr())
	assert.Equal(t, "1918181833n", msg.To.Tag())
	assert.Equal(t, `"J Rosenberg \\\""`, msg.From.DisplayName())
	assert.Equal(t, "sip:jdrosen@example.com", msg.From.Addr())
	assert.Equal(t, "98asjd8", msg.From.Tag())
	assert.EqualValues(t, 68, msg.MaxFwd)
	assert.EqualValues(t, 9, msg.CSeq.Num)
	assert.EqualValues(t, "INVITE", msg.CSeq.Method)
	assert.Equal(t, 3, msg.Vias.Count())
	assert.Equal(t, 1, msg.Routes.Count())
	assert.Equal(t, 1, msg.Contacts.Count())
	assert.Equal(t, "sip:jdrosen@example.com", msg.Contacts.First().Location())

	h := msg.Headers.FindByName("s")
	assert.NotNil(t, h)
	assert.Equal(t, "", h.Value())

	h = msg.Headers.FindByName("NewFangledHeader")
	assert.NotNil(t, h)
	assert.Equal(t, "newfangled value\r\n continued newfangled value", h.Value())

	h = msg.Headers.FindByName("UnknownHeaderWithUnusualValue")
	assert.NotNil(t, h)
	assert.Equal(t, ";;,,;;,;", h.Value())

	h = msg.Headers.FindByName("Content-type")
	assert.NotNil(t, h)
	assert.Equal(t, "application/sdp", h.Value())

	h = msg.Headers.Find(SIPHdrCSeq)
	assert.NotNil(t, h)
	assert.Equal(t, "0009\r\n  INVITE", h.Value())

	assert.Equal(t, 14, msg.Headers.Count())
}

// 3.1.1.2.  Wide Range of Valid Characters
func TestMsgParseTortureIntmeth(t *testing.T) {
	str := "!interesting-Method0123456789_*+`.%indeed'~ " +
		"sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*" +
		":&it+has=1,weird!*pas$wo~d_too.(doesn't-it)" +
		"@example.com SIP/2.0\r\n" +

		"Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK-.!%66*_+`'~\r\n" +

		"To: \"BEL:\\\x07 NUL:\\\x00 DEL:\\\x7F\" " +
		"<sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*" +
		"@example.com>\r\n" +

		"From: token1~` token2'+_ token3*%!.- <sip:mundane@example.com>" +
		";fromParam''~+*_!.-%=" +
		"\"\xD1\x80\xD0\xB0\xD0\xB1\xD0\xBE\xD1\x82\xD0\xB0\xD1\x8E\xD1\x89\xD0\xB8\xD0\xB9\"" +
		";tag=_token~1'+`*%!-.\r\n" +

		"Call-ID: intmeth.word%ZK-!.*_+'@word`~)(><:\\/\"][?}{\r\n" +
		"CSeq: 139122385 !interesting-Method0123456789_*+`.%indeed'~\r\n" +
		"Max-Forwards: 255\r\n" +

		"extensionHeader-!.%*+_`'~:" +
		"\xEF\xBB\xBF\xE5\xA4\xA7\xE5\x81\x9C\xE9\x9B\xBB\r\n" +

		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())
	assert.Equal(t, "sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*"+
		":&it+has=1,weird!*pas$wo~d_too.(doesn't-it)@example.com",
		msg.ReqLine.RequestURI())
	assert.Equal(t, "\"BEL:\\\x07 NUL:\\\x00 DEL:\\\x7F\"",
		msg.To.DisplayName())

	h := msg.Headers.FindByName("extensionHeader-!.%*+_`'~")
	assert.NotNil(t, h)
	assert.Equal(t, "\xEF\xBB\xBF\xE5\xA4\xA7\xE5\x81\x9C\xE9\x9B\xBB", h.Value())

	h = msg.Headers.Find(SIPHdrCSeq)
	assert.NotNil(t, h)
	assert.Equal(t, "139122385 !interesting-Method0123456789_*+`.%indeed'~", h.Value())

	h = msg.Headers.FindByName("content-length")
	assert.NotNil(t, h)
	assert.Equal(t, "0", h.Value())

	assert.Equal(t, 8, msg.Headers.Count())
}

// TODO: esc01, escnull, esc02
// 3.1.1.6.  Message with No LWS between Display Name and <
func TestMsgParseTortureLwsdisp(t *testing.T) {
	str := "OPTIONS sip:user@example.com SIP/2.0\r\n" +
		"To: sip:user@example.com\r\n" +
		"From: caller<sip:caller@example.com>;tag=323\r\n" +
		"Max-Forwards: 70\r\n" +
		"Call-ID: lwsdisp.1234abcd@funky.example.com\r\n" +
		"CSeq: 60 OPTIONS\r\n" +
		"Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n" +
		"l: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())
	assert.Equal(t, "caller", msg.From.DisplayName())
	assert.Equal(t, "sip:caller@example.com", msg.From.Addr())
	assert.Equal(t, "323", msg.From.Tag())
}

// 3.1.1.7.  Long Values in Header Fields
func TestMsgParseTortureLongreq(t *testing.T) {
	str := "INVITE sip:user@example.com SIP/2.0\r\n" +
		// <allOneLine>
		"To: \"I have a user name of " + strings.Repeat("extreme", 10) +
		" proportion\"<sip:user@example.com:6000;" +
		"unknownparam1=very" + strings.Repeat("long", 20) + "value;" +
		"longparam" + strings.Repeat("name", 25) + "=shortvalue;" +
		"very" + strings.Repeat("long", 25) + "ParameterNameWithNoValue>\r\n" +
		// </allOneLine>
		// <allOneLine>
		"F: sip:" + strings.Repeat("amazinglylongcallername", 5) + "@example.net" +
		";tag=12" + strings.Repeat("982", 50) + "424" +
		";unknownheaderparam" + strings.Repeat("name", 20) + "=" +
		"unknowheaderparam" + strings.Repeat("value", 15) +
		";unknownValueless" + strings.Repeat("paramname", 10) + "\r\n" +
		// </allOneLine>
		"Call-ID: longreq.one" + strings.Repeat("really", 20) + "longcallid\r\n" +
		"CSeq: 3882340 INVITE\r\n" +
		// <allOneLine>
		"Unknown-" + strings.Repeat("Long", 20) + "-Name:" +
		"unknown-" + strings.Repeat("long", 20) + "-value;" +
		"unknown-" + strings.Repeat("long", 20) + "-parameter-name =" +
		"unknown-" + strings.Repeat("long", 20) + "-parameter-value\r\n" +
		// </allOneLine>

		"Via: SIP/2.0/TCP sip33.example.com\r\n" +
		"v: SIP/2.0/TCP sip32.example.com\r\n" +
		"V: SIP/2.0/TCP sip31.example.com\r\n" +
		"Via: SIP/2.0/TCP sip30.example.com\r\n" +
		"ViA: SIP/2.0/TCP sip29.example.com\r\n" +
		"VIa: SIP/2.0/TCP sip28.example.com\r\n" +
		"VIA: SIP/2.0/TCP sip27.example.com\r\n" +
		"via: SIP/2.0/TCP sip26.example.com\r\n" +
		"viA: SIP/2.0/TCP sip25.example.com\r\n" +
		"vIa: SIP/2.0/TCP sip24.example.com\r\n" +
		"vIA: SIP/2.0/TCP sip23.example.com\r\n" +
		"V :  SIP/2.0/TCP sip22.example.com\r\n" +
		"v :  SIP/2.0/TCP sip21.example.com\r\n" +
		"V  : SIP/2.0/TCP sip20.example.com\r\n" +
		"v  : SIP/2.0/TCP sip19.example.com\r\n" +
		"Via : SIP/2.0/TCP sip18.example.com\r\n" +
		"Via  : SIP/2.0/TCP sip17.example.com\r\n" +
		"Via: SIP/2.0/TCP sip16.example.com\r\n" +
		"Via: SIP/2.0/TCP sip15.example.com\r\n" +
		"Via: SIP/2.0/TCP sip14.example.com\r\n" +
		"Via: SIP/2.0/TCP sip13.example.com\r\n" +
		"Via: SIP/2.0/TCP sip12.example.com\r\n" +
		"Via: SIP/2.0/TCP sip11.example.com\r\n" +
		"Via: SIP/2.0/TCP sip10.example.com\r\n" +
		"Via: SIP/2.0/TCP sip9.example.com\r\n" +
		"Via: SIP/2.0/TCP sip8.example.com\r\n" +
		"Via: SIP/2.0/TCP sip7.example.com\r\n" +
		"Via: SIP/2.0/TCP sip6.example.com\r\n" +
		"Via: SIP/2.0/TCP sip5.example.com\r\n" +
		"Via: SIP/2.0/TCP sip4.example.com\r\n" +
		"Via: SIP/2.0/TCP sip3.example.com\r\n" +
		"Via: SIP/2.0/TCP sip2.example.com\r\n" +
		"Via: SIP/2.0/TCP sip1.example.com\r\n" +
		// <allOneLine>
		"Via: SIP/2.0/TCP host.example.com;received=192.0.2.5;" +
		"branch=very" + strings.Repeat("long", 50) + "branchvalue\r\n" +
		// </allOneLine>
		"Max-Forwards: 70\r\n" +
		// <allOneLine>
		"Contact: <sip:" + strings.Repeat("amazinglylongcallername", 5) +
		"@host5.example.net>\r\n" +
		// </allOneLine>
		"Content-Type: application/sdp\r\n" +
		"l: 150\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())
	assert.Equal(t, 34, msg.Vias.Count())
	assert.Equal(t, 1, msg.Contacts.Count())
	assert.Equal(t, "longreq.one"+strings.Repeat("really", 20)+"longcallid",
		msg.CallID)

}

// TODO: dblreq
// 3.1.1.9.  Semicolon-Separated Parameters in URI User Part
func TestMsgParseTortureSemiUri(t *testing.T) {
	str := "OPTIONS sip:user;par=u%40example.net@example.com SIP/2.0\r\n" +
		"To: sip:j_user@example.com\r\n" +
		"From: sip:caller@example.org;tag=33242\r\n" +
		"Max-Forwards: 3\r\n" +
		"Call-ID: semiuri.0ha0isndaksdj\r\n" +
		"CSeq: 8 OPTIONS\r\n" +
		"Accept: application/sdp, application/pkcs7-mime,\r\n" +
		"        multipart/mixed, multipart/signed,\r\n" +
		"        message/sip, message/sipfrag\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKkdjuw\r\n" +
		"l: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())
	ruri := msg.ReqLine.RequestURI()
	uri := URIParse([]byte(ruri))
	assert.Equal(t, "user;par=u%40example.net", uri.User())

	h := msg.Headers.FindByName("accept")
	assert.NotNil(t, h)
	assert.Equal(t, "application/sdp, application/pkcs7-mime,\r\n"+
		"        multipart/mixed, multipart/signed,\r\n"+
		"        message/sip, message/sipfrag", h.Value())

	h = msg.Headers.Find(SIPHdrCSeq)
	assert.NotNil(t, h)
	assert.Equal(t, "8 OPTIONS", h.Value())

	h = msg.Headers.Find(SIPHdrContentLength)
	assert.NotNil(t, h)
	assert.Equal(t, "0", h.Value())

	assert.Equal(t, 8, msg.Headers.Count())
}

// TODO: transports, mpart01
// 3.1.1.12.  Unusual Reason Phrase
func TestMsgParseTortureUnReason(t *testing.T) {
	//<allOneLine>
	str := "SIP/2.0 200 = 2**3 * 5**2 " +
		"\xD0\xBD\xD0\xBE\x20\xD1\x81\xD1\x82\xD0\xBE\x20\xD0\xB4" +
		"\xD0\xB5\xD0\xB2\xD1\x8F\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82" +
		"\xD0\xBE\x20\xD0\xB4\xD0\xB5\xD0\xB2\xD1\x8F\xD1\x82\xD1" +
		"\x8C\x20\x2D\x20\xD0\xBF\xD1\x80\xD0\xBE\xD1\x81\xD1\x82" +
		"\xD0\xBE\xD0\xB5\r\n" +
		//</allOneLine>
		"Via: SIP/2.0/UDP 192.0.2.198;branch=z9hG4bK1324923\r\n" +
		"Call-ID: unreason.1234ksdfak3j2erwedfsASdf\r\n" +
		"CSeq: 35 INVITE\r\n" +
		"From: sip:user@example.com;tag=11141343\r\n" +
		"To: sip:user@example.edu;tag=2229\r\n" +
		"Content-Length: 154\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Contact: <sip:user@host198.example.com>\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsResponse())
	assert.Contains(t, msg.StatusLine.Reason(), "= 2**3 * 5**2 ")
}

// 3.1.1.13.  Empty Reason Phrase
func TestMsgParseTortureNoReason(t *testing.T) {
	str := "SIP/2.0 100 \r\n" +
		"Via: SIP/2.0/UDP 192.0.2.105;branch=z9hG4bK2398ndaoe\r\n" +
		"Call-ID: noreason.asndj203insdf99223ndf\r\n" +
		"CSeq: 35 INVITE\r\n" +
		"From: <sip:user@example.com>;tag=39ansfi3\r\n" +
		"To: <sip:user@example.edu>;tag=902jndnke3\r\n" +
		"Content-Length: 0\r\n" +
		"Contact: <sip:user@host105.example.com>\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsResponse())
	assert.Empty(t, msg.StatusLine.Reason())
}

// 3.1.2.1.  Extraneous Header Field Separators
func TestMsgParseTortureBadinv01(t *testing.T) {
	str := "INVITE sip:user@example.com SIP/2.0\r\n" +
		"To: sip:j.user@example.com\r\n" +
		"From: sip:caller@example.net;tag=134161461246\r\n" +
		"Max-Forwards: 7\r\n" +
		"Call-ID: badinv01.0ha0isndaksdjasdf3234nas\r\n" +
		"CSeq: 8 INVITE\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.15;;,;,,\r\n" +
		"Contact: \"Joe\" <sip:joe@example.org>;;;;\r\n" +
		"Content-Length: 152\r\n" +
		"Content-Type: application/sdp\r\n\r\n"
	// The Via header field of this request contains additional semicolons
	// and commas without parameters or values.
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Via: SIP/2.0/UDP 192.0.2.15;;,;")
}

// TODO: cler (!)

// 3.1.2.3.  Negative Content-Length
func TestMsgParseTortureNcl(t *testing.T) {
	str := "INVITE sip:user@example.com SIP/2.0\r\n" +
		"Max-Forwards: 254\r\n" +
		"To: sip:j.user@example.com\r\n" +
		"From: sip:caller@example.net;tag=32394234\r\n" +
		"Call-ID: ncl.0ha0isndaksdj2193423r542w35\r\n" +
		"CSeq: 0 INVITE\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.53;branch=z9hG4bKkdjuw\r\n" +
		"Contact: <sip:caller@example53.example.net>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: -999\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Content-Length: -999")
}

// TODO: scalar02,scalarlg

// 3.1.2.6.  Unterminated Quoted String in Display Name
// To: "Mr. J. User <sip:j.user@example.com>
func TestMsgParseTortureQuotbal(t *testing.T) {
	str := "INVITE sip:user@example.com SIP/2.0\r\n" +
		"To: \"Mr. J. User <sip:j.user@example.com>\r\n" +
		"From: sip:caller@example.net;tag=93334\r\n" +
		"Max-Forwards: 10\r\n" +
		"Call-ID: quotbal.aksdj\r\n" +
		"Contact: <sip:caller@host59.example.net>\r\n" +
		"CSeq: 8 INVITE\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.59:5050;branch=z9hG4bKkdjuw39234\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 152\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "To: \"Mr. J. User <sip")
}

// 3.1.2.7.  <> Enclosing Request-URI
func TestMsgParseTortureLtgtruri(t *testing.T) {
	str := "INVITE <sip:user@example.com> SIP/2.0\r\n" +
		"To: sip:user@example.com\r\n" +
		"From: sip:caller@example.net;tag=39291\r\n" +
		"Max-Forwards: 23\r\n" +
		"Call-ID: ltgtruri.1@192.0.2.5\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.5\r\n" +
		"Contact: <sip:caller@host5.example.net>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 159\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "INVITE <sip:user@example.com> SIP/2.0")
}

// 3.1.2.8.  Malformed SIP Request-URI (embedded LWS)
func TestMsgParseTortureLwsRuri(t *testing.T) {
	str := "INVITE sip:user@example.com; lr SIP/2.0\r\n" +
		"To: sip:user@example.com;tag=3xfe-9921883-z9f\r\n" +
		"From: sip:caller@example.net;tag=231413434\r\n" +
		"Max-Forwards: 5\r\n" +
		"Call-ID: lwsruri.asdfasdoeoi2323-asdfwrn23-asd834rk423\r\n" +
		"CSeq: 2130706432 INVITE\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKkdjuw2395\r\n" +
		"Contact: <sip:caller@host1.example.net>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 159\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "INVITE sip:user@example.com; lr SIP/2.0")
}

// 3.1.2.9.  Multiple SP Separating Request-Line Elements
// This INVITE has illegal multiple SP characters between elements of
// the start line.
func TestMsgParseTortureLwsStart(t *testing.T) {
	str := "INVITE  sip:user@example.com  SIP/2.0\r\n" +
		"Max-Forwards: 8\r\n" +
		"To: sip:user@example.com\r\n" +
		"From: sip:caller@example.net;tag=8814\r\n" +
		"Call-ID: lwsstart.dfknq234oi243099adsdfnawe3@example.com\r\n" +
		"CSeq: 1893884 INVITE\r\n" +
		"Via: SIP/2.0/UDP host1.example.com;branch=z9hG4bKkdjuw3923\r\n" +
		"Contact: <sip:caller@host1.example.net>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 150\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "INVITE  sip:user@example.com  SIP/2.0")
}

// 3.1.2.10.  SP Characters at End of Request-Line
// OPTIONS sip:remote-target@example.com SIP/2.0<hex>2020</hex>
func TestMsgParseTortureTrws(t *testing.T) {
	str := "OPTIONS sip:remote-target@example.com SIP/2.0  \r\n" +
		"Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK299342093\r\n" +
		"To: <sip:remote-target@example.com>\r\n" +
		"From: <sip:local-resource@example.com>;tag=329429089\r\n" +
		"Call-ID: trws.oicu34958239neffasdhr2345r\r\n" +
		"Accept: application/sdp\r\n" +
		"CSeq: 238923 OPTIONS\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "OPTIONS sip:remote-target@example.com SIP/2.0  ")
}

// TODO: escruri(?),baddate,regbadct(?)

// 3.1.2.14.  Spaces within addr-spec
func TestMsgParseTortureRegBadCt(t *testing.T) {
	str := "OPTIONS sip:user@example.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP host4.example.com:5060;branch=z9hG4bKkdju43234\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: \"Bell, Alexander\" <sip:a.g.bell@example.com>;tag=433423\r\n" +
		"To: \"Watson, Thomas\" < sip:t.watson@example.org >\r\n" +
		"Call-ID: badaspec.sdf0234n2nds0a099u23h3hnnw009cdkne3\r\n" +
		"Accept: application/sdp\r\n" +
		"CSeq: 3923239 OPTIONS\r\n" +
		"l: 0\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "< sip:t.watson@example.org >")
}

// 3.1.2.15.  Non-token Characters in Display Name
func TestMsgParseTortureBadDn(t *testing.T) {
	str := "OPTIONS sip:t.watson@example.org SIP/2.0\r\n" +
		"Via:     SIP/2.0/UDP c.example.com:5060;branch=z9hG4bKkdjuw\r\n" +
		"Max-Forwards:      70\r\n" +
		"From:    Bell, Alexander <sip:a.g.bell@example.com>;tag=43\r\n" +
		"To:      Watson, Thomas <sip:t.watson@example.org>\r\n" +
		"Call-ID: baddn.31415@c.example.com\r\n" +
		"Accept: application/sdp\r\n" +
		"CSeq:    3923239 OPTIONS\r\n" +
		"l: 0\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "From:    Bell, Alexander <sip")
}

// application level
// TODO: badvers(?),mismatch01,mismatch02,bigcode,badbranch,insuf,unkscm,novelsc,
//       unksm2,bext01,invut,regaut01,multi01,mcl01,bcast,zeromf,cparam01,cparam02,
//       regescrt,sdp01,inv2543
