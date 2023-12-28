package go_groth16

/*
#cgo CFLAGS:-I${SRCDIR}/libgroth16/include
#include <stdio.h>
#include <stdlib.h>
#include <groth16.h>
*/
import "C"
import (
	"unsafe"
)

const BufferSize = 4096

func VerifyBn254(vk string, provingOutput string) bool {
	vkC := C.CString(vk)
	provingOutputC := C.CString(provingOutput)
	res := C.groth16_verify_bn254(vkC, provingOutputC)
	return res == 1
}

type ProvingContext struct {
	ctx    unsafe.Pointer
	buffer unsafe.Pointer
	output *string
}

func LoadContext(wasmPath string, r1csPath string, zkeyPath string) *ProvingContext {
	buffer := C.malloc(C.size_t(BufferSize))
	wasmPathC := C.CString(wasmPath)
	r1csPathC := C.CString(r1csPath)
	zkeyPathC := C.CString(zkeyPath)
	ctx := C.load_context_bn254(wasmPathC, r1csPathC, zkeyPathC)

	return &ProvingContext{ctx: ctx, buffer: buffer, output: nil}
}

func (c *ProvingContext) Prove(input string) string {
	inputC := C.CString(input)
	defer C.free(unsafe.Pointer(inputC))
	res := C.prove_bn254(c.ctx, inputC, (*C.char)(c.buffer), BufferSize)
	if res < 0 {
		println("failed")
	}
	return C.GoString((*C.char)(c.buffer))
}

func (c *ProvingContext) VerifyingKey() string {
	size := C.verifying_key_size_bn254(c.ctx)
	tempBuffer := C.malloc(C.size_t(size + 1))
	defer C.free(tempBuffer)
	res := C.export_verifying_key_bn254(c.ctx, (*C.char)(tempBuffer), size+1)
	if res < 0 {
		println("failed")
	}
	return C.GoString((*C.char)(tempBuffer))
}

func (c *ProvingContext) Free() {
	C.free(c.buffer)
	//C.free_context_bn254(c.ctx) // TODO: Figure out why enabling this will cause this error "Process finished with the exit code 132 (interrupted by signal 4:SIGILL)"
}
