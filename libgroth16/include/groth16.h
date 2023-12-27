#ifndef _BLS_H_
#define _BLS_H_

int groth16_verify_bn254(const char* vk, int vk_len, const char* inputs, int input_len, const char* proof, int proof_len);
void* load_context_bn254(const char* wasm_path, const char* r1cs_path, const char* zkey_path);
int prove_bn254(const void* ctx, const char* input, char* buf, int max_len);
void free_context_bn254(void* ctx);

#endif