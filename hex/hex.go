package hex

// Byte converts a single byte to an ASCII
// byte slice representation.
//
// Example:
//  string(hex.Byte(0xff))
//  Output: "ff"
func Byte(b byte) []byte {
	var res [2]byte
	res[0], res[1] = (b>>4)+'0', (b&0b0000_1111)+'0'
	if (b >> 4) > 9 {
		res[0] = (b >> 4) + 'A' - 10
	}
	if (b & 0b0000_1111) > 9 {
		res[1] = (b & 0b0000_1111) + 'A' - 10
	}
	return res[:]
}

// Bytes converts a binary slice of bytes to an ASCII
// hex representation.
//
// Example:
//  string(hex.Bytes([]byte{0xff,0xaa}))
//  Output: "ffaa"
func Bytes(b []byte) []byte {
	o := make([]byte, len(b)*2)
	for i := 0; i < len(b); i++ {
		aux := Byte(b[i])
		o[i*2] = aux[0]
		o[i*2+1] = aux[1]
	}
	return o
}

// PrintBytes print binary slice as hexadecimal with minimal memory allocation. uses `print()`
func PrintBytes(b []byte) {
	for i := 0; i < len(b); i++ {
		print(string(Byte(b[i])))
	}
}

// Decode turns an ASCII represented hexadecimal string b to
// binary ignoring the non-hexa digits.
func Decode(b []byte) []byte {
	out := make([]byte, 0, len(b)/2)
	var ib int
	for i := range b {
		char := b[i]
		switch {
		case char >= 'A' && char <= 'F':
			char -= 'A' - 10
		case char >= 'a' && char <= 'f':
			char -= 'a' - 10
		case char >= '0' && char <= '9':
			char -= '0'
		default:
			continue
		}
		if ib%2 == 1 {
			out[ib/2] |= char
		} else {
			out = append(out, char<<4)
		}
		ib++
	}
	return out
}
