package go_groth16

/*
#cgo CFLAGS:-I${SRCDIR}/libgroth16/include
#include <stdio.h>
#include <stdlib.h>
#include <groth16.h>
*/
import "C"
import "unsafe"

const BufferSize = 4096

func VerifyBn254(vk []byte, inputs [][]byte, proof []byte) int {
	var input []byte
	for _, slice := range inputs {
		input = append(input, slice...)
	}
	vkC := (*C.char)(unsafe.Pointer(&vk[0]))
	vkL := C.int(len(vk))
	inputC := (*C.char)(unsafe.Pointer(&input[0]))
	inputL := C.int(len(input))
	proofC := (*C.char)(unsafe.Pointer(&proof[0]))
	proofL := C.int(len(proof))

	//val := int(C.empty(vkC, vkL, inputC, inputL, proofC, proofL))

	val := int(C.groth16_verify_bn254(vkC, vkL, inputC, inputL, proofC, proofL))
	return val
}

type ProvingContext struct {
	ctx    unsafe.Pointer
	buffer unsafe.Pointer
	output *string
}

func LoadContext(wasmPath string, r1csPath string, zkeyPath string) *ProvingContext {
	println("loading context")
	defer println("loaded context")
	buffer := C.malloc(C.size_t(BufferSize))
	wasmPathC := C.CString(wasmPath)
	r1csPathC := C.CString(r1csPath)
	zkeyPathC := C.CString(zkeyPath)
	ctx := C.load_context_bn254(wasmPathC, r1csPathC, zkeyPathC)

	return &ProvingContext{ctx: ctx, buffer: buffer, output: nil}
}

func (c *ProvingContext) Prove(input string) string {
	println("proving")
	defer println("proved")
	inputC := C.CString(input)
	defer C.free(unsafe.Pointer(inputC))
	res := C.prove_bn254(c.ctx, inputC, (*C.char)(c.buffer), BufferSize)
	if res < 0 {
		println("failed")
	}
	return C.GoString((*C.char)(c.buffer))
}

func (c *ProvingContext) Free() {
	C.free(c.buffer)
	//C.free_context_bn254(c.ctx) // TODO: Figure out why enabling this will cause this error "Process finished with the exit code 132 (interrupted by signal 4:SIGILL)"
}
