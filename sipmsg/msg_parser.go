
//line msg_parser.rl:1
// -*-go-*-
//
// SIP(s) URI parser
package sipmsg


//line msg_parser.rl:7

//line msg_parser.go:12
var _msg_actions []byte = []byte{
	0, 1, 0, 1, 1, 1, 2, 2, 0, 
	1, 
}

var _msg_key_offsets []byte = []byte{
	0, 0, 2, 4, 6, 7, 9, 12, 
	14, 17, 19, 21, 23, 24, 52, 80, 
	81, 87, 93, 95, 97, 99, 101, 103, 
}

var _msg_trans_keys []byte = []byte{
	83, 115, 73, 105, 80, 112, 47, 48, 
	57, 46, 48, 57, 48, 57, 32, 48, 
	57, 48, 57, 48, 57, 48, 57, 32, 
	13, 37, 60, 62, 96, 127, 0, 8, 
	10, 31, 34, 35, 91, 94, 123, 125, 
	192, 223, 224, 239, 240, 247, 248, 251, 
	252, 253, 254, 255, 13, 37, 60, 62, 
	96, 127, 0, 8, 10, 31, 34, 35, 
	91, 94, 123, 125, 192, 223, 224, 239, 
	240, 247, 248, 251, 252, 253, 254, 255, 
	10, 48, 57, 65, 70, 97, 102, 48, 
	57, 65, 70, 97, 102, 128, 191, 128, 
	191, 128, 191, 128, 191, 128, 191, 
}

var _msg_single_lengths []byte = []byte{
	0, 2, 2, 2, 1, 0, 1, 0, 
	1, 0, 0, 0, 1, 6, 6, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
}

var _msg_range_lengths []byte = []byte{
	0, 0, 0, 0, 0, 1, 1, 1, 
	1, 1, 1, 1, 0, 11, 11, 0, 
	3, 3, 1, 1, 1, 1, 1, 0, 
}

var _msg_index_offsets []byte = []byte{
	0, 0, 3, 6, 9, 11, 13, 16, 
	18, 21, 23, 25, 27, 29, 47, 65, 
	67, 71, 75, 77, 79, 81, 83, 85, 
}

var _msg_indicies []byte = []byte{
	0, 0, 1, 2, 2, 1, 3, 3, 
	1, 4, 1, 5, 1, 6, 5, 1, 
	7, 1, 8, 7, 1, 9, 1, 10, 
	1, 11, 1, 12, 1, 14, 15, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	16, 17, 18, 19, 20, 1, 13, 22, 
	23, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 24, 25, 26, 27, 28, 1, 
	21, 29, 1, 30, 30, 30, 1, 21, 
	21, 21, 1, 21, 1, 24, 1, 25, 
	1, 26, 1, 27, 1, 1, 
}

var _msg_trans_targs []byte = []byte{
	2, 0, 3, 4, 5, 6, 7, 8, 
	9, 10, 11, 12, 13, 14, 15, 16, 
	18, 19, 20, 21, 22, 14, 15, 16, 
	18, 19, 20, 21, 22, 23, 17, 
}

var _msg_trans_actions []byte = []byte{
	1, 0, 0, 0, 0, 0, 0, 0, 
	3, 1, 0, 0, 3, 1, 7, 1, 
	1, 1, 1, 1, 1, 0, 3, 0, 
	0, 0, 0, 0, 0, 5, 0, 
}

const msg_start int = 1
const msg_first_final int = 23
const msg_error int = 0

const msg_en_msg int = 1


//line msg_parser.rl:8

func parseHeader(data []byte) *header {
	h := &header{buf: data}
	cs := 0 // current state. entery point = 0
	l := ptr(len(data))
	var p, // data pointer
		m, // marker
		pe, eof ptr = 0, 0, l, l
	var pos []pl

//line msg_parser.rl:27

	
//line msg_parser.go:107
	{
	cs = msg_start
	}

//line msg_parser.rl:29
	
//line msg_parser.go:114
	{
	var _klen int
	var _trans int
	var _acts int
	var _nacts uint
	var _keys int
	if p == pe {
		goto _test_eof
	}
	if cs == 0 {
		goto _out
	}
_resume:
	_keys = int(_msg_key_offsets[cs])
	_trans = int(_msg_index_offsets[cs])

	_klen = int(_msg_single_lengths[cs])
	if _klen > 0 {
		_lower := int(_keys)
		var _mid int
		_upper := int(_keys + _klen - 1)
		for {
			if _upper < _lower {
				break
			}

			_mid = _lower + ((_upper - _lower) >> 1)
			switch {
			case data[p] < _msg_trans_keys[_mid]:
				_upper = _mid - 1
			case data[p] > _msg_trans_keys[_mid]:
				_lower = _mid + 1
			default:
				_trans += int(_mid - int(_keys))
				goto _match
			}
		}
		_keys += _klen
		_trans += _klen
	}

	_klen = int(_msg_range_lengths[cs])
	if _klen > 0 {
		_lower := int(_keys)
		var _mid int
		_upper := int(_keys + (_klen << 1) - 2)
		for {
			if _upper < _lower {
				break
			}

			_mid = _lower + (((_upper - _lower) >> 1) & ^1)
			switch {
			case data[p] < _msg_trans_keys[_mid]:
				_upper = _mid - 2
			case data[p] > _msg_trans_keys[_mid + 1]:
				_lower = _mid + 2
			default:
				_trans += int((_mid - int(_keys)) >> 1)
				goto _match
			}
		}
		_trans += _klen
	}

_match:
	_trans = int(_msg_indicies[_trans])
	cs = int(_msg_trans_targs[_trans])

	if _msg_trans_actions[_trans] == 0 {
		goto _again
	}

	_acts = int(_msg_trans_actions[_trans])
	_nacts = uint(_msg_actions[_acts]); _acts++
	for ; _nacts > 0; _nacts-- {
		_acts++
		switch _msg_actions[_acts-1] {
		case 0:
//line msg_parser.rl:19
 m = p 
		case 1:
//line msg_parser.rl:20
 pos = append(pos, pl{m, p}) 
		case 2:
//line msg_parser.rl:25
setStatusLine(h, pos)
//line msg_parser.go:202
		}
	}

_again:
	if cs == 0 {
		goto _out
	}
	p++
	if p != pe {
		goto _resume
	}
	_test_eof: {}
	_out: {}
	}

//line msg_parser.rl:30
	if cs >= msg_first_final {
		println(m, eof)
		return h
	}
	return nil
}

func setStatusLine(h *header, pos []pl) {
	h.resp = statusLine{
		ver: pos[0],
		code: pos[1],
		reason: pos[2],
	}
}
