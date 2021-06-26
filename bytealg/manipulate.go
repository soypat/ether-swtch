package bytealg

// Swap provides in place byte slice swap
func Swap(a, b []byte) {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		a[i], b[i] = b[i], a[i]
	}
}
