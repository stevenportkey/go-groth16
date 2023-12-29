using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Groth16.Net
{
    public unsafe class Verifier : Groth16Base
    {
        static readonly Lazy<groth16_verify_bn254> groth16_verify_bn254
            = LazyDelegate<groth16_verify_bn254>(nameof(groth16_verify_bn254));

        public static bool VerifyBn254(string verifyingKey, string provingOutput)
        {
            Span<byte> inputInBytes = Encoding.ASCII.GetBytes(verifyingKey);
            Span<byte> provingOutputInBytes = Encoding.ASCII.GetBytes(provingOutput);
            var verified = -100;

            fixed (byte* inputPtr = &MemoryMarshal.GetReference(inputInBytes),
                   provingOutputPtr = &MemoryMarshal.GetReference(provingOutputInBytes))
            {
                verified = groth16_verify_bn254.Value(inputPtr, provingOutputPtr);
            }

            return verified == 1;
        }
    }
}