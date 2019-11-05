//line parser_ctype.rl:1
// -*-go-*-
//
// Content Type header parser
package sipmsg

//line parser_ctype.rl:7

//line parser_ctype.go:12
var _ctype_actions []byte = []byte{
	0, 1, 0, 1, 1, 1, 2, 1, 3,
	2, 4, 6, 2, 5, 6,
}

var _ctype_key_offsets []byte = []byte{
	0, 0, 14, 30, 34, 35, 37, 40,
	57, 58, 60, 76, 80, 81, 83, 86,
	103, 104, 106, 122, 140, 144, 145, 147,
	150, 168, 169, 171, 189, 190, 192, 195,
	211, 212, 214, 220, 222, 224, 226, 228,
	230, 248, 252,
}

var _ctype_trans_keys []byte = []byte{
	33, 37, 39, 126, 42, 43, 45, 46,
	48, 57, 65, 90, 95, 122, 9, 13,
	32, 33, 37, 39, 47, 126, 42, 43,
	45, 57, 65, 90, 95, 122, 9, 13,
	32, 47, 10, 9, 32, 9, 32, 47,
	9, 13, 32, 33, 37, 39, 126, 42,
	43, 45, 46, 48, 57, 65, 90, 95,
	122, 10, 9, 32, 9, 32, 33, 37,
	39, 126, 42, 43, 45, 46, 48, 57,
	65, 90, 95, 122, 9, 13, 32, 59,
	10, 9, 32, 9, 32, 59, 9, 13,
	32, 33, 37, 39, 126, 42, 43, 45,
	46, 48, 57, 65, 90, 95, 122, 10,
	9, 32, 9, 32, 33, 37, 39, 126,
	42, 43, 45, 46, 48, 57, 65, 90,
	95, 122, 9, 13, 32, 33, 37, 39,
	61, 126, 42, 43, 45, 46, 48, 57,
	65, 90, 95, 122, 9, 13, 32, 61,
	10, 9, 32, 9, 32, 61, 9, 13,
	32, 33, 34, 37, 39, 126, 42, 43,
	45, 46, 48, 57, 65, 90, 95, 122,
	10, 9, 32, 9, 13, 32, 33, 34,
	37, 39, 126, 42, 43, 45, 46, 48,
	57, 65, 90, 95, 122, 10, 9, 32,
	9, 32, 34, 9, 13, 34, 92, 32,
	126, 192, 223, 224, 239, 240, 247, 248,
	251, 252, 253, 10, 9, 32, 0, 9,
	11, 12, 14, 127, 128, 191, 128, 191,
	128, 191, 128, 191, 128, 191, 9, 13,
	32, 33, 37, 39, 59, 126, 42, 43,
	45, 46, 48, 57, 65, 90, 95, 122,
	9, 13, 32, 59, 9, 13, 32, 33,
	37, 39, 59, 126, 42, 43, 45, 46,
	48, 57, 65, 90, 95, 122,
}

var _ctype_single_lengths []byte = []byte{
	0, 4, 8, 4, 1, 2, 3, 7,
	1, 2, 6, 4, 1, 2, 3, 7,
	1, 2, 6, 8, 4, 1, 2, 3,
	8, 1, 2, 8, 1, 2, 3, 4,
	1, 2, 0, 0, 0, 0, 0, 0,
	8, 4, 8,
}

var _ctype_range_lengths []byte = []byte{
	0, 5, 4, 0, 0, 0, 0, 5,
	0, 0, 5, 0, 0, 0, 0, 5,
	0, 0, 5, 5, 0, 0, 0, 0,
	5, 0, 0, 5, 0, 0, 0, 6,
	0, 0, 3, 1, 1, 1, 1, 1,
	5, 0, 5,
}

var _ctype_index_offsets []int16 = []int16{
	0, 0, 10, 23, 28, 30, 33, 37,
	50, 52, 55, 67, 72, 74, 77, 81,
	94, 96, 99, 111, 125, 130, 132, 135,
	139, 153, 155, 158, 172, 174, 177, 181,
	192, 194, 197, 201, 203, 205, 207, 209,
	211, 225, 230,
}

var _ctype_indicies []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 2, 3, 2, 4, 4, 4,
	5, 4, 4, 4, 4, 4, 1, 6,
	7, 6, 8, 1, 9, 1, 10, 10,
	1, 10, 10, 8, 1, 8, 11, 8,
	12, 12, 12, 12, 12, 12, 12, 12,
	12, 1, 13, 1, 14, 14, 1, 14,
	14, 12, 12, 12, 12, 12, 12, 12,
	12, 12, 1, 15, 16, 15, 17, 1,
	18, 1, 19, 19, 1, 19, 19, 17,
	1, 17, 20, 17, 21, 21, 21, 21,
	21, 21, 21, 21, 21, 1, 22, 1,
	23, 23, 1, 23, 23, 21, 21, 21,
	21, 21, 21, 21, 21, 21, 1, 24,
	25, 24, 26, 26, 26, 27, 26, 26,
	26, 26, 26, 26, 1, 28, 29, 28,
	30, 1, 31, 1, 32, 32, 1, 32,
	32, 30, 1, 33, 34, 33, 35, 36,
	35, 35, 35, 35, 35, 35, 35, 35,
	1, 37, 1, 38, 38, 1, 39, 40,
	39, 35, 36, 35, 35, 35, 35, 35,
	35, 35, 35, 1, 41, 1, 42, 42,
	1, 42, 42, 43, 1, 43, 44, 45,
	46, 43, 47, 48, 49, 50, 51, 1,
	52, 1, 43, 43, 1, 43, 43, 43,
	1, 43, 1, 47, 1, 48, 1, 49,
	1, 50, 1, 53, 54, 53, 55, 55,
	55, 56, 55, 55, 55, 55, 55, 55,
	1, 57, 58, 57, 59, 1, 60, 61,
	60, 62, 62, 62, 63, 62, 62, 62,
	62, 62, 62, 1,
}

var _ctype_trans_targs []byte = []byte{
	2, 0, 3, 4, 2, 7, 3, 4,
	7, 5, 6, 8, 40, 9, 10, 11,
	12, 15, 13, 14, 16, 19, 17, 18,
	20, 21, 19, 24, 20, 21, 24, 22,
	23, 24, 25, 42, 31, 26, 27, 27,
	28, 29, 30, 31, 32, 41, 34, 35,
	36, 37, 38, 39, 33, 11, 12, 40,
	15, 11, 12, 15, 11, 12, 42, 15,
}

var _ctype_trans_actions []byte = []byte{
	1, 0, 3, 3, 0, 3, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 1, 0, 0,
	7, 7, 0, 7, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 0, 0, 1,
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 5, 5, 0,
	5, 12, 12, 12, 9, 9, 0, 9,
}

var _ctype_eof_actions []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	5, 12, 9,
}

const ctype_start int = 1
const ctype_first_final int = 40
const ctype_error int = 0

const ctype_en_main int = 1

//line parser_ctype.rl:8

func parseContentType(data []byte) (*ContentType, error) {
	cs := 0
	l := ptr(len(data))
	var p, m, pe, eof ptr = 0, 0, l, l
	var prm_name, prm_val pl
	ct := &ContentType{}

//line parser_ctype.rl:39

//line parser_ctype.go:177
	{
		cs = ctype_start
	}

//line parser_ctype.rl:42

//line parser_ctype.go:184
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
		_keys = int(_ctype_key_offsets[cs])
		_trans = int(_ctype_index_offsets[cs])

		_klen = int(_ctype_single_lengths[cs])
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
				case data[p] < _ctype_trans_keys[_mid]:
					_upper = _mid - 1
				case data[p] > _ctype_trans_keys[_mid]:
					_lower = _mid + 1
				default:
					_trans += int(_mid - int(_keys))
					goto _match
				}
			}
			_keys += _klen
			_trans += _klen
		}

		_klen = int(_ctype_range_lengths[cs])
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
				case data[p] < _ctype_trans_keys[_mid]:
					_upper = _mid - 2
				case data[p] > _ctype_trans_keys[_mid+1]:
					_lower = _mid + 2
				default:
					_trans += int((_mid - int(_keys)) >> 1)
					goto _match
				}
			}
			_trans += _klen
		}

	_match:
		_trans = int(_ctype_indicies[_trans])
		cs = int(_ctype_trans_targs[_trans])

		if _ctype_trans_actions[_trans] == 0 {
			goto _again
		}

		_acts = int(_ctype_trans_actions[_trans])
		_nacts = uint(_ctype_actions[_acts])
		_acts++
		for ; _nacts > 0; _nacts-- {
			_acts++
			switch _ctype_actions[_acts-1] {
			case 0:
//line parser_ctype.rl:17
				m = p
			case 1:
//line parser_ctype.rl:18
				ct.mtype = data[m:p]
			case 2:
//line parser_ctype.rl:19
				ct.msubtype = data[m:p]
			case 3:
//line parser_ctype.rl:20
				prm_name.p = m
				prm_name.l = p
			case 4:
//line parser_ctype.rl:21
				prm_val.p = m
				prm_val.l = p
			case 5:
//line parser_ctype.rl:22
				prm_val.p = m + 1
				prm_val.l = p - 1
			case 6:
//line parser_ctype.rl:23

				if ct.params == nil {
					ct.params = make(map[string][]byte)
				}
				ct.params[string(data[prm_name.p:prm_name.l])] = data[prm_val.p:prm_val.l]

//line parser_ctype.go:289
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
	_test_eof:
		{
		}
		if p == eof {
			__acts := _ctype_eof_actions[cs]
			__nacts := uint(_ctype_actions[__acts])
			__acts++
			for ; __nacts > 0; __nacts-- {
				__acts++
				switch _ctype_actions[__acts-1] {
				case 2:
//line parser_ctype.rl:19
					ct.msubtype = data[m:p]
				case 4:
//line parser_ctype.rl:21
					prm_val.p = m
					prm_val.l = p
				case 5:
//line parser_ctype.rl:22
					prm_val.p = m + 1
					prm_val.l = p - 1
				case 6:
//line parser_ctype.rl:23

					if ct.params == nil {
						ct.params = make(map[string][]byte)
					}
					ct.params[string(data[prm_name.p:prm_name.l])] = data[prm_val.p:prm_val.l]

//line parser_ctype.go:325
				}
			}
		}

	_out:
		{
		}
	}

//line parser_ctype.rl:43

	if cs >= ctype_first_final {
		return ct, nil
	}
	return nil, ErrorSIPHeader.msg("Invalid content type header: %s", data[m:p])
}
