using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Groth16.Net
{
    public unsafe class Prover : Groth16Base, IDisposable
    {
        public static Prover Create(string wasmPath, string r1csPath, string zkeyPath)
        {
            var ctx = LoadContextBn2546(wasmPath, r1csPath, zkeyPath);
            var prover = new Prover();
            prover._ctx = ctx;
            return prover;
        }

        IntPtr _ctx;
        public IntPtr Context => _ctx;

        static readonly Lazy<load_context_bn254> load_context_bn254
            = Groth16Base.LazyDelegate<load_context_bn254>(nameof(load_context_bn254));

        static readonly Lazy<free_context_bn254> free_context_bn254
            = Groth16Base.LazyDelegate<free_context_bn254>(nameof(free_context_bn254));

        static readonly Lazy<verifying_key_size_bn254> verifying_key_size_bn254
            = Groth16Base.LazyDelegate<verifying_key_size_bn254>(nameof(verifying_key_size_bn254));

        static readonly Lazy<export_verifying_key_bn254> export_verifying_key_bn254
            = Groth16Base.LazyDelegate<export_verifying_key_bn254>(nameof(export_verifying_key_bn254));

        static readonly Lazy<prove_bn254> prove_bn254
            = Groth16Base.LazyDelegate<prove_bn254>(nameof(prove_bn254));


        static IntPtr LoadContextBn2546(string wasmPath, string r1csPath, string zkeyPath)
        {
            var ctx = IntPtr.Zero;
            var wasm = Encoding.UTF8.GetBytes(wasmPath).AsSpan();
            var r1cs = Encoding.UTF8.GetBytes(r1csPath).AsSpan();
            var zkey = Encoding.UTF8.GetBytes(zkeyPath).AsSpan();


            fixed (byte* wasmPathPtr = &MemoryMarshal.GetReference(wasm), r1csPathPtr =
                       &MemoryMarshal.GetReference(r1cs), zkeyPathPtr = &MemoryMarshal.GetReference(zkey))

            {
                ctx = load_context_bn254.Value(wasmPathPtr, r1csPathPtr, zkeyPathPtr);
            }

            return ctx;
        }

        public string ExportVerifyingKeyBn254()
        {
            var buf = new byte[verifying_key_size_bn254.Value(_ctx) + 1];
            fixed (byte* bufPtr = buf)
            {
                export_verifying_key_bn254.Value(_ctx, bufPtr, buf.Length);
            }

            var charArray = Encoding.UTF8.GetChars(buf);

            return new string(charArray);
        }

        public string ProveBn254(IDictionary<string, IList<string>> input)
        {
            var buffer = new byte[1048576]; // 1MB

            var inputString = input.ToJsonString();
            Console.WriteLine(inputString);
            Span<byte> inputInBytes = Encoding.ASCII.GetBytes(inputString);
            Span<byte> output = buffer;
            var returnedBytes = 0;

            fixed (byte* inputPtr = &MemoryMarshal.GetReference(inputInBytes),
                   buffPtr = &MemoryMarshal.GetReference(output))
            {
                returnedBytes = prove_bn254.Value(_ctx, inputPtr, buffPtr, buffer.Length);
            }

            if (returnedBytes < 0) throw new Exception($"failed with code {returnedBytes}");

            var charArray = Encoding.UTF8.GetChars(buffer.TakeWhile(v => v != 0).ToArray());
            return new string(charArray);
        }

        public int VerifyingKeySizeBn254()
        {
            return verifying_key_size_bn254.Value(_ctx);
        }

        public void Dispose()
        {
            if (_ctx != IntPtr.Zero)
            {
                free_context_bn254.Value(_ctx);
                _ctx = IntPtr.Zero;
            }
        }
    }
}