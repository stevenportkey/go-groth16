using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Groth16.Net
{
    internal class InternalProvingOutput
    {
        public InternalProvingOutput(IList<string> publicInputs, string proof)
        {
            PublicInputs = publicInputs;
            Proof = proof;
        }

        private IList<string> PublicInputs { get; set; }

        private string Proof { get; set; }

        public string ToJsonString()
        {
            return $"{{\"public_inputs\":{PublicInputs.ToJsonString()},\"proof\":\"{Proof}\"}}";
        }
    }

    public unsafe class Verifier : Groth16Base
    {
        static readonly Lazy<groth16_verify_bn254> groth16_verify_bn254
            = LazyDelegate<groth16_verify_bn254>(nameof(groth16_verify_bn254));

        public static bool VerifyBn254(string verifyingKey, IList<string> publicInputs, string proof)
        {
            var provingOutput = new InternalProvingOutput(publicInputs, proof).ToJsonString();
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