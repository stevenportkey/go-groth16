package go_groth16

/*
#cgo LDFLAGS:-lgroth16 -lm -ldl
#cgo windows,amd64 LDFLAGS: -lws2_32 -luserenv -lbcrypt
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/libgroth16/lib/linux/amd64
#cgo linux,arm64 LDFLAGS:-L${SRCDIR}/libgroth16/lib/linux/arm64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/libgroth16/lib/darwin/amd64
#cgo darwin,arm64 LDFLAGS:-L${SRCDIR}/libgroth16/lib/darwin/arm64
#cgo windows,amd64 LDFLAGS:-L${SRCDIR}/libgroth16/lib/windows/amd64
*/
import "C"
