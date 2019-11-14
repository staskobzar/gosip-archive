// +build gofuzz

package sdp

func Fuzz(data []byte) int {
	msg, err := Parse(data)
	if err != nil {
		if msg != nil {
			panic("msg != nil on error")
		}
		return 0
	}

	return 1
}
