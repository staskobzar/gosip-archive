//line parser_challenge.rl:1
// -*-go-*-
//
// HTTP Challenge parser
package sipmsg

//line parser_challenge.rl:7

//line parser_challenge.go:12
var _challenge_actions []byte = []byte{
	0, 1, 0, 1, 1, 1, 2, 1, 3,
	1, 4, 1, 5, 1, 6, 1, 7,
	1, 8, 1, 9, 1, 10,
}

var _challenge_key_offsets []int16 = []int16{
	0, 0, 1, 2, 3, 4, 5, 6,
	9, 26, 27, 29, 45, 47, 49, 51,
	53, 55, 57, 59, 61, 65, 66, 68,
	71, 76, 77, 79, 83, 85, 86, 90,
	91, 93, 96, 98, 100, 102, 104, 106,
	108, 110, 112, 114, 118, 119, 121, 124,
	128, 129, 131, 135, 136, 138, 141, 146,
	159, 165, 175, 188, 201, 202, 204, 210,
	216, 230, 246, 261, 267, 273, 291, 297,
	303, 317, 324, 332, 340, 348, 350, 357,
	366, 368, 371, 373, 376, 378, 381, 384,
	385, 390, 392, 398, 404, 410, 416, 420,
	423, 424, 427, 428, 437, 446, 454, 462,
	470, 478, 480, 486, 495, 504, 513, 515,
	518, 521, 522, 523, 529, 535, 537, 539,
	541, 543, 547, 548, 550, 553, 557, 558,
	560, 564, 565, 567, 570, 586, 587, 589,
	595, 597, 599, 601, 603, 605, 607, 609,
	611, 613, 615, 619, 620, 622, 625, 629,
	630, 632, 636, 637, 639, 642, 658, 659,
	661, 667, 669, 671, 673, 675, 677, 679,
	681, 685, 686, 688, 691, 695, 696, 698,
	702, 703, 705, 708, 710, 712, 714, 716,
	719, 721, 723, 725, 727, 729, 731, 733,
	735, 739, 740, 742, 745, 749, 750, 752,
	756, 757, 759, 762, 778, 779, 781, 787,
	789, 791, 793, 795, 797, 799, 801, 803,
	805, 809, 810, 812, 815, 822, 823, 825,
	831, 833, 835, 837, 839, 841, 843, 845,
	850, 854, 858, 862, 866, 870, 874, 878,
}

var _challenge_trans_keys []byte = []byte{
	68, 105, 103, 101, 115, 116, 9, 13,
	32, 9, 13, 32, 65, 68, 78, 79,
	81, 82, 83, 97, 100, 110, 111, 113,
	114, 115, 10, 9, 32, 9, 32, 65,
	68, 78, 79, 81, 82, 83, 97, 100,
	110, 111, 113, 114, 115, 76, 108, 71,
	103, 79, 111, 82, 114, 73, 105, 84,
	116, 72, 104, 77, 109, 9, 13, 32,
	61, 10, 9, 32, 9, 32, 61, 9,
	13, 32, 77, 109, 10, 9, 32, 9,
	32, 77, 109, 68, 100, 53, 9, 13,
	32, 44, 10, 9, 32, 9, 32, 44,
	83, 115, 69, 101, 83, 115, 83, 115,
	79, 111, 77, 109, 65, 97, 73, 105,
	78, 110, 9, 13, 32, 61, 10, 9,
	32, 9, 32, 61, 9, 13, 32, 34,
	10, 9, 32, 9, 13, 32, 34, 10,
	9, 32, 9, 32, 34, 47, 65, 90,
	97, 122, 32, 33, 34, 37, 61, 95,
	126, 36, 59, 64, 90, 97, 122, 32,
	47, 65, 90, 97, 122, 43, 58, 45,
	46, 48, 57, 65, 90, 97, 122, 33,
	37, 47, 61, 93, 95, 126, 36, 59,
	63, 90, 97, 122, 32, 33, 34, 37,
	61, 95, 126, 36, 59, 63, 90, 97,
	122, 10, 9, 32, 48, 57, 65, 70,
	97, 102, 48, 57, 65, 70, 97, 102,
	32, 33, 34, 37, 47, 61, 95, 126,
	36, 59, 63, 90, 97, 122, 32, 33,
	34, 37, 58, 61, 64, 91, 95, 126,
	36, 59, 63, 90, 97, 122, 32, 33,
	34, 37, 58, 61, 64, 95, 126, 36,
	59, 63, 90, 97, 122, 48, 57, 65,
	70, 97, 102, 48, 57, 65, 70, 97,
	102, 32, 33, 34, 37, 47, 61, 63,
	64, 95, 126, 36, 57, 58, 59, 65,
	90, 97, 122, 48, 57, 65, 70, 97,
	102, 48, 57, 65, 70, 97, 102, 32,
	33, 34, 37, 61, 91, 95, 126, 36,
	59, 63, 90, 97, 122, 58, 48, 57,
	65, 70, 97, 102, 58, 93, 48, 57,
	65, 70, 97, 102, 58, 93, 48, 57,
	65, 70, 97, 102, 58, 93, 48, 57,
	65, 70, 97, 102, 58, 93, 58, 48,
	57, 65, 70, 97, 102, 46, 58, 93,
	48, 57, 65, 70, 97, 102, 48, 57,
	46, 48, 57, 48, 57, 46, 48, 57,
	48, 57, 93, 48, 57, 93, 48, 57,
	93, 32, 34, 47, 58, 63, 48, 57,
	32, 34, 47, 63, 48, 57, 32, 34,
	47, 63, 48, 57, 32, 34, 47, 63,
	48, 57, 32, 34, 47, 63, 48, 57,
	32, 34, 47, 63, 46, 48, 57, 46,
	46, 48, 57, 46, 46, 58, 93, 48,
	57, 65, 70, 97, 102, 46, 58, 93,
	48, 57, 65, 70, 97, 102, 58, 93,
	48, 57, 65, 70, 97, 102, 58, 93,
	48, 57, 65, 70, 97, 102, 58, 93,
	48, 57, 65, 70, 97, 102, 58, 93,
	48, 57, 65, 70, 97, 102, 58, 93,
	48, 57, 65, 70, 97, 102, 46, 58,
	93, 48, 57, 65, 70, 97, 102, 46,
	58, 93, 48, 57, 65, 70, 97, 102,
	46, 58, 93, 48, 57, 65, 70, 97,
	102, 48, 57, 46, 48, 57, 46, 48,
	57, 46, 58, 48, 57, 65, 70, 97,
	102, 48, 57, 65, 70, 97, 102, 79,
	111, 78, 110, 67, 99, 69, 101, 9,
	13, 32, 61, 10, 9, 32, 9, 32,
	61, 9, 13, 32, 34, 10, 9, 32,
	9, 13, 32, 34, 10, 9, 32, 9,
	32, 34, 9, 13, 34, 92, 32, 126,
	192, 223, 224, 239, 240, 247, 248, 251,
	252, 253, 10, 9, 32, 0, 9, 11,
	12, 14, 127, 128, 191, 128, 191, 128,
	191, 128, 191, 128, 191, 80, 112, 65,
	97, 81, 113, 85, 117, 69, 101, 9,
	13, 32, 61, 10, 9, 32, 9, 32,
	61, 9, 13, 32, 34, 10, 9, 32,
	9, 13, 32, 34, 10, 9, 32, 9,
	32, 34, 9, 13, 34, 92, 32, 126,
	192, 223, 224, 239, 240, 247, 248, 251,
	252, 253, 10, 9, 32, 0, 9, 11,
	12, 14, 127, 128, 191, 128, 191, 128,
	191, 128, 191, 128, 191, 79, 111, 80,
	112, 9, 13, 32, 61, 10, 9, 32,
	9, 32, 61, 9, 13, 32, 34, 10,
	9, 32, 9, 13, 32, 34, 10, 9,
	32, 9, 32, 34, 65, 97, 85, 117,
	84, 116, 72, 104, 34, 44, 45, 73,
	105, 78, 110, 84, 116, 34, 44, 69,
	101, 65, 97, 76, 108, 77, 109, 9,
	13, 32, 61, 10, 9, 32, 9, 32,
	61, 9, 13, 32, 34, 10, 9, 32,
	9, 13, 32, 34, 10, 9, 32, 9,
	32, 34, 9, 13, 34, 92, 32, 126,
	192, 223, 224, 239, 240, 247, 248, 251,
	252, 253, 10, 9, 32, 0, 9, 11,
	12, 14, 127, 128, 191, 128, 191, 128,
	191, 128, 191, 128, 191, 84, 116, 65,
	97, 76, 108, 69, 101, 9, 13, 32,
	61, 10, 9, 32, 9, 32, 61, 9,
	13, 32, 70, 84, 102, 116, 10, 9,
	32, 9, 32, 70, 84, 102, 116, 65,
	97, 76, 108, 83, 115, 69, 101, 82,
	114, 85, 117, 69, 101, 9, 13, 32,
	44, 45, 9, 13, 32, 44, 9, 13,
	32, 44, 9, 13, 32, 44, 9, 13,
	32, 44, 9, 13, 32, 44, 9, 13,
	32, 44, 9, 13, 32, 44, 9, 13,
	32, 44,
}

var _challenge_single_lengths []byte = []byte{
	0, 1, 1, 1, 1, 1, 1, 3,
	17, 1, 2, 16, 2, 2, 2, 2,
	2, 2, 2, 2, 4, 1, 2, 3,
	5, 1, 2, 4, 2, 1, 4, 1,
	2, 3, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 4, 1, 2, 3, 4,
	1, 2, 4, 1, 2, 3, 1, 7,
	2, 2, 7, 7, 1, 2, 0, 0,
	8, 10, 9, 0, 0, 10, 0, 0,
	8, 1, 2, 2, 2, 2, 1, 3,
	0, 1, 0, 1, 0, 1, 1, 1,
	5, 0, 4, 4, 4, 4, 4, 1,
	1, 1, 1, 3, 3, 2, 2, 2,
	2, 2, 0, 3, 3, 3, 0, 1,
	1, 1, 1, 0, 0, 2, 2, 2,
	2, 4, 1, 2, 3, 4, 1, 2,
	4, 1, 2, 3, 4, 1, 2, 0,
	0, 0, 0, 0, 0, 2, 2, 2,
	2, 2, 4, 1, 2, 3, 4, 1,
	2, 4, 1, 2, 3, 4, 1, 2,
	0, 0, 0, 0, 0, 0, 2, 2,
	4, 1, 2, 3, 4, 1, 2, 4,
	1, 2, 3, 2, 2, 2, 2, 3,
	2, 2, 2, 2, 2, 2, 2, 2,
	4, 1, 2, 3, 4, 1, 2, 4,
	1, 2, 3, 4, 1, 2, 0, 0,
	0, 0, 0, 0, 2, 2, 2, 2,
	4, 1, 2, 3, 7, 1, 2, 6,
	2, 2, 2, 2, 2, 2, 2, 5,
	4, 4, 4, 4, 4, 4, 4, 4,
}

var _challenge_range_lengths []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 2, 3,
	2, 4, 3, 3, 0, 0, 3, 3,
	3, 3, 3, 3, 3, 4, 3, 3,
	3, 3, 3, 3, 3, 0, 3, 3,
	1, 1, 1, 1, 1, 1, 1, 0,
	0, 1, 1, 1, 1, 1, 0, 1,
	0, 1, 0, 3, 3, 3, 3, 3,
	3, 0, 3, 3, 3, 3, 1, 1,
	1, 0, 0, 3, 3, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 6, 0, 0, 3,
	1, 1, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 6, 0, 0,
	3, 1, 1, 1, 1, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 6, 0, 0, 3, 1,
	1, 1, 1, 1, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

var _challenge_index_offsets []int16 = []int16{
	0, 0, 2, 4, 6, 8, 10, 12,
	16, 34, 36, 39, 56, 59, 62, 65,
	68, 71, 74, 77, 80, 85, 87, 90,
	94, 100, 102, 105, 110, 113, 115, 120,
	122, 125, 129, 132, 135, 138, 141, 144,
	147, 150, 153, 156, 161, 163, 166, 170,
	175, 177, 180, 185, 187, 190, 194, 198,
	209, 214, 221, 232, 243, 245, 248, 252,
	256, 268, 282, 295, 299, 303, 318, 322,
	326, 338, 343, 349, 355, 361, 364, 369,
	376, 378, 381, 383, 386, 388, 391, 394,
	396, 402, 404, 410, 416, 422, 428, 433,
	436, 438, 441, 443, 450, 457, 463, 469,
	475, 481, 484, 488, 495, 502, 509, 511,
	514, 517, 519, 521, 525, 529, 532, 535,
	538, 541, 546, 548, 551, 555, 560, 562,
	565, 570, 572, 575, 579, 590, 592, 595,
	599, 601, 603, 605, 607, 609, 612, 615,
	618, 621, 624, 629, 631, 634, 638, 643,
	645, 648, 653, 655, 658, 662, 673, 675,
	678, 682, 684, 686, 688, 690, 692, 695,
	698, 703, 705, 708, 712, 717, 719, 722,
	727, 729, 732, 736, 739, 742, 745, 748,
	752, 755, 758, 761, 764, 767, 770, 773,
	776, 781, 783, 786, 790, 795, 797, 800,
	805, 807, 810, 814, 825, 827, 830, 834,
	836, 838, 840, 842, 844, 847, 850, 853,
	856, 861, 863, 866, 870, 878, 880, 883,
	890, 893, 896, 899, 902, 905, 908, 911,
	917, 922, 927, 932, 937, 942, 947, 952,
}

var _challenge_trans_targs []byte = []byte{
	2, 0, 3, 0, 4, 0, 5, 0,
	6, 0, 7, 0, 8, 9, 8, 0,
	8, 9, 8, 12, 38, 117, 141, 166,
	188, 212, 12, 38, 117, 141, 166, 188,
	212, 0, 10, 0, 11, 11, 0, 11,
	11, 12, 38, 117, 141, 166, 188, 212,
	12, 38, 117, 141, 166, 188, 212, 0,
	13, 13, 0, 14, 14, 0, 15, 15,
	0, 16, 16, 0, 17, 17, 0, 18,
	18, 0, 19, 19, 0, 20, 20, 0,
	20, 21, 20, 24, 0, 22, 0, 23,
	23, 0, 23, 23, 24, 0, 24, 25,
	24, 28, 28, 0, 26, 0, 27, 27,
	0, 27, 27, 28, 28, 0, 29, 29,
	0, 231, 0, 30, 31, 30, 8, 0,
	32, 0, 33, 33, 0, 33, 33, 8,
	0, 35, 35, 0, 36, 36, 0, 37,
	37, 0, 232, 232, 0, 39, 39, 0,
	40, 40, 0, 41, 41, 0, 42, 42,
	0, 43, 43, 0, 43, 44, 43, 47,
	0, 45, 0, 46, 46, 0, 46, 46,
	47, 0, 47, 48, 47, 54, 0, 49,
	0, 50, 50, 0, 50, 51, 50, 54,
	0, 52, 0, 53, 53, 0, 53, 53,
	54, 0, 55, 57, 57, 0, 56, 55,
	233, 115, 55, 55, 55, 55, 55, 55,
	0, 56, 55, 57, 57, 0, 57, 58,
	57, 57, 57, 57, 0, 59, 62, 64,
	59, 59, 59, 59, 59, 59, 59, 0,
	56, 59, 233, 62, 59, 59, 59, 59,
	59, 59, 0, 61, 0, 234, 234, 0,
	63, 63, 63, 0, 59, 59, 59, 0,
	56, 59, 233, 62, 65, 59, 59, 59,
	59, 59, 59, 0, 56, 66, 233, 67,
	59, 66, 59, 73, 66, 66, 66, 66,
	66, 0, 56, 66, 233, 67, 69, 66,
	72, 66, 66, 66, 66, 66, 0, 68,
	68, 68, 0, 66, 66, 66, 0, 56,
	69, 233, 70, 59, 69, 59, 72, 69,
	69, 69, 59, 69, 69, 0, 71, 71,
	71, 0, 69, 69, 69, 0, 56, 59,
	233, 62, 59, 73, 59, 59, 59, 59,
	59, 0, 114, 74, 74, 74, 0, 78,
	88, 75, 75, 75, 0, 78, 88, 76,
	76, 76, 0, 78, 88, 77, 77, 77,
	0, 78, 88, 0, 101, 79, 74, 74,
	0, 80, 78, 88, 99, 75, 75, 0,
	81, 0, 82, 97, 0, 83, 0, 84,
	95, 0, 85, 0, 88, 86, 0, 88,
	87, 0, 88, 0, 56, 233, 59, 89,
	59, 0, 90, 0, 56, 233, 59, 59,
	91, 0, 56, 233, 59, 59, 92, 0,
	56, 233, 59, 59, 93, 0, 56, 233,
	59, 59, 94, 0, 56, 233, 59, 59,
	0, 84, 96, 0, 84, 0, 82, 98,
	0, 82, 0, 80, 78, 88, 100, 76,
	76, 0, 80, 78, 88, 77, 77, 77,
	0, 110, 88, 102, 102, 102, 0, 106,
	88, 103, 103, 103, 0, 106, 88, 104,
	104, 104, 0, 106, 88, 105, 105, 105,
	0, 106, 88, 0, 107, 102, 102, 0,
	80, 106, 88, 108, 103, 103, 0, 80,
	106, 88, 109, 104, 104, 0, 80, 106,
	88, 105, 105, 105, 0, 111, 0, 80,
	112, 0, 80, 113, 0, 80, 0, 101,
	0, 116, 116, 116, 0, 55, 55, 55,
	0, 118, 118, 0, 119, 119, 0, 120,
	120, 0, 121, 121, 0, 121, 122, 121,
	125, 0, 123, 0, 124, 124, 0, 124,
	124, 125, 0, 125, 126, 125, 132, 0,
	127, 0, 128, 128, 0, 128, 129, 128,
	132, 0, 130, 0, 131, 131, 0, 131,
	131, 132, 0, 132, 133, 235, 135, 132,
	136, 137, 138, 139, 140, 0, 134, 0,
	132, 132, 0, 132, 132, 132, 0, 132,
	0, 136, 0, 137, 0, 138, 0, 139,
	0, 142, 142, 0, 143, 143, 0, 144,
	144, 0, 145, 145, 0, 146, 146, 0,
	146, 147, 146, 150, 0, 148, 0, 149,
	149, 0, 149, 149, 150, 0, 150, 151,
	150, 157, 0, 152, 0, 153, 153, 0,
	153, 154, 153, 157, 0, 155, 0, 156,
	156, 0, 156, 156, 157, 0, 157, 158,
	236, 160, 157, 161, 162, 163, 164, 165,
	0, 159, 0, 157, 157, 0, 157, 157,
	157, 0, 157, 0, 161, 0, 162, 0,
	163, 0, 164, 0, 167, 167, 0, 168,
	168, 0, 168, 169, 168, 172, 0, 170,
	0, 171, 171, 0, 171, 171, 172, 0,
	172, 173, 172, 179, 0, 174, 0, 175,
	175, 0, 175, 176, 175, 179, 0, 177,
	0, 178, 178, 0, 178, 178, 179, 0,
	180, 180, 0, 181, 181, 0, 182, 182,
	0, 183, 183, 0, 233, 179, 184, 0,
	185, 185, 0, 186, 186, 0, 187, 187,
	0, 233, 179, 0, 189, 189, 0, 190,
	190, 0, 191, 191, 0, 192, 192, 0,
	192, 193, 192, 196, 0, 194, 0, 195,
	195, 0, 195, 195, 196, 0, 196, 197,
	196, 203, 0, 198, 0, 199, 199, 0,
	199, 200, 199, 203, 0, 201, 0, 202,
	202, 0, 202, 202, 203, 0, 203, 204,
	237, 206, 203, 207, 208, 209, 210, 211,
	0, 205, 0, 203, 203, 0, 203, 203,
	203, 0, 203, 0, 207, 0, 208, 0,
	209, 0, 210, 0, 213, 213, 0, 214,
	214, 0, 215, 215, 0, 216, 216, 0,
	216, 217, 216, 220, 0, 218, 0, 219,
	219, 0, 219, 219, 220, 0, 220, 221,
	220, 224, 228, 224, 228, 0, 222, 0,
	223, 223, 0, 223, 223, 224, 228, 224,
	228, 0, 225, 225, 0, 226, 226, 0,
	227, 227, 0, 238, 238, 0, 229, 229,
	0, 230, 230, 0, 239, 239, 0, 30,
	31, 30, 8, 34, 0, 30, 31, 30,
	8, 0, 233, 60, 233, 8, 0, 234,
	31, 234, 8, 0, 30, 31, 30, 8,
	0, 30, 31, 30, 8, 0, 30, 31,
	30, 8, 0, 30, 31, 30, 8, 0,
	30, 31, 30, 8, 0,
}

var _challenge_trans_actions []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 1, 1, 0, 0, 0,
	5, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 5, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 5, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 5, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 5, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 5, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	5, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 5, 0, 0,
	0, 0, 0, 0, 0, 5, 0, 0,
	0, 0, 0, 5, 0, 0, 0, 0,
	0, 5, 0, 0, 0, 0, 0, 5,
	0, 0, 0, 0, 0, 5, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 1, 1, 1, 1, 0,
	0, 0, 0, 0, 0, 1, 1, 1,
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 1,
	1, 1, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 11, 11, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 13, 13, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 1,
	1, 1, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 19,
	19, 19, 19, 0, 0, 21, 21, 21,
	21, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 7, 7, 7, 7,
	0, 9, 9, 9, 9, 0, 3, 3,
	3, 3, 0, 17, 17, 17, 17, 0,
	15, 15, 15, 15, 0,
}

var _challenge_eof_actions []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 19,
	21, 0, 0, 7, 9, 3, 17, 15,
}

const challenge_start int = 1
const challenge_first_final int = 231
const challenge_error int = 0

const challenge_en_challenge int = 1

//line parser_challenge.rl:8

func parseChallenge(data []byte) (*Challenge, error) {
	cs := 0
	l := ptr(len(data))
	var p, m, pe, eof ptr = 0, 0, l, l
	ch := &Challenge{}

//line parser_challenge.rl:39

//line parser_challenge.go:564
	{
		cs = challenge_start
	}

//line parser_challenge.rl:42

//line parser_challenge.go:571
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
		_keys = int(_challenge_key_offsets[cs])
		_trans = int(_challenge_index_offsets[cs])

		_klen = int(_challenge_single_lengths[cs])
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
				case data[p] < _challenge_trans_keys[_mid]:
					_upper = _mid - 1
				case data[p] > _challenge_trans_keys[_mid]:
					_lower = _mid + 1
				default:
					_trans += int(_mid - int(_keys))
					goto _match
				}
			}
			_keys += _klen
			_trans += _klen
		}

		_klen = int(_challenge_range_lengths[cs])
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
				case data[p] < _challenge_trans_keys[_mid]:
					_upper = _mid - 2
				case data[p] > _challenge_trans_keys[_mid+1]:
					_lower = _mid + 2
				default:
					_trans += int((_mid - int(_keys)) >> 1)
					goto _match
				}
			}
			_trans += _klen
		}

	_match:
		cs = int(_challenge_trans_targs[_trans])

		if _challenge_trans_actions[_trans] == 0 {
			goto _again
		}

		_acts = int(_challenge_trans_actions[_trans])
		_nacts = uint(_challenge_actions[_acts])
		_acts++
		for ; _nacts > 0; _nacts-- {
			_acts++
			switch _challenge_actions[_acts-1] {
			case 0:
//line parser_challenge.rl:16
				m = p
			case 1:
//line parser_challenge.rl:17
				ch.realm = data[m+1 : p-1]
			case 2:
//line parser_challenge.rl:18
				ch.domain = data[m:p]
			case 3:
//line parser_challenge.rl:19
				ch.nonce = data[m+1 : p-1]
			case 4:
//line parser_challenge.rl:20
				ch.opaque = data[m+1 : p-1]
			case 5:
//line parser_challenge.rl:24
				ch.qop |= QOPAuth
			case 6:
//line parser_challenge.rl:24
				ch.qop |= QOPAuthInt
			case 7:
//line parser_challenge.rl:31
				ch.stale = true
			case 8:
//line parser_challenge.rl:31
				ch.stale = false
			case 9:
//line parser_challenge.rl:33
				ch.algo = AlgoMD5
			case 10:
//line parser_challenge.rl:33
				ch.algo = AlgoMD5sess
//line parser_challenge.go:682
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
			__acts := _challenge_eof_actions[cs]
			__nacts := uint(_challenge_actions[__acts])
			__acts++
			for ; __nacts > 0; __nacts-- {
				__acts++
				switch _challenge_actions[__acts-1] {
				case 1:
//line parser_challenge.rl:17
					ch.realm = data[m+1 : p-1]
				case 3:
//line parser_challenge.rl:19
					ch.nonce = data[m+1 : p-1]
				case 4:
//line parser_challenge.rl:20
					ch.opaque = data[m+1 : p-1]
				case 7:
//line parser_challenge.rl:31
					ch.stale = true
				case 8:
//line parser_challenge.rl:31
					ch.stale = false
				case 9:
//line parser_challenge.rl:33
					ch.algo = AlgoMD5
				case 10:
//line parser_challenge.rl:33
					ch.algo = AlgoMD5sess
//line parser_challenge.go:722
				}
			}
		}

	_out:
		{
		}
	}

//line parser_challenge.rl:43

	if cs >= challenge_first_final {
		return ch, nil
	}
	return nil, ErrorSIPHeader.msg("Invalid challenge: %s", data[m:p])
}