package sdp

func TestBuildNoMedia(t *testing.T) {
	str := "v=0\r\n" +
		"o=alice 2890844526 2890844526 IN IP4 host.atlanta.example.com\r\n" +
		"s=\r\n" +
		"c=IN IP4 host.atlanta.example.com\r\n" +
		"t=0 0\r\n"
	msg, err := 
}
