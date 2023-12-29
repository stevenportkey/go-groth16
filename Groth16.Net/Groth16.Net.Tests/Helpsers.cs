using Newtonsoft.Json;

namespace Groth16.Net.Tests;

public static class Helpers
{
    public static ProvingOutput ParseProvingOutput(string provingOutput)
    {
        var provingOutputObj = JsonConvert.DeserializeObject<ProvingOutput>(provingOutput);
        return provingOutputObj;
    }
}