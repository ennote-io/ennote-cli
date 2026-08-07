package crypto

import "runtime"

func ZeroMemory(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
