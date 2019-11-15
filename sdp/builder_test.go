package sdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildInit(t *testing.T) {
	id := string(idFromNTP())
	str := "v=0\r\n" +
		"o=- " + id + " " + id + " IN IP4 atlanta.com\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n"

	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	assert.Equal(t, str, msg.String())
}

func TestBuildSubjectInfoUri(t *testing.T) {
	str := "s=Online training\r\n" +
		"i=SIP and SDP with certification\r\n" +
		"u=http://lib.sip.com/2019-11-02/readme.pdf\r\n" +
		"t=0 0\r\n"
	msg := NewMessage("192.168.1.1")
	assert.NotNil(t, msg)

	msg.SetSubject("Online training")
	msg.SetInfo("SIP and SDP with certification")
	msg.SetURI("http://lib.sip.com/2019-11-02/readme.pdf")
	assert.Contains(t, msg.String(), str)
}
