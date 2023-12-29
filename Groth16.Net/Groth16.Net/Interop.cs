using System;
using System.Runtime.InteropServices;

namespace Groth16.Net
{
    public unsafe delegate int groth16_verify_bn254(byte* vk, byte* proving_output);

    public unsafe delegate IntPtr load_context_bn254(byte* wasm_path, byte* r1cs_path, byte* zkey_path);

    public unsafe delegate int verifying_key_size_bn254(IntPtr ctx);

    public unsafe delegate int export_verifying_key_bn254(IntPtr ctx, byte* buf, int max_len);

    public unsafe delegate int prove_bn254(IntPtr ctx, byte* input, byte* buf, int max_len);

    public unsafe delegate void free_context_bn254(IntPtr ctx);

    /// <summary>
    /// Type for error and illegal callback functions,
    /// </summary>
    /// <param name="message">message: error message.</param>
    /// <param name="data">data: callback marker, it is set by user together with callback.</param>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public unsafe delegate void ErrorCallbackDelegate(string message, void* data);
}