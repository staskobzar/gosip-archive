// +build gofuzz

package sipmsg

func Fuzz(data []byte) int {
	msg, err := MsgParse(data)
	if err != nil {
		if msg != nil {
			panic("msg != nil on error")
		}
		return 0
	}

	_ = msg.String()
	return 1
}
