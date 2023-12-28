#ifndef _BLS_H_
#define _BLS_H_

int groth16_verify_bn254(const char* vk, const char* proving_output);
void* load_context_bn254(const char* wasm_path, const char* r1cs_path, const char* zkey_path);
int verifying_key_size_bn254(const void* ctx);
int export_verifying_key_bn254(const void* ctx, char* buf, int max_len);
int prove_bn254(const void* ctx, const char* input, char* buf, int max_len);
void free_context_bn254(void* ctx);

#endif