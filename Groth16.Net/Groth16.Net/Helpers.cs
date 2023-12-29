using System.Collections.Generic;
using System.Data.Common;
using System.Linq;

namespace Groth16.Net
{
    using InputType = IDictionary<string, IList<string>>;

    public static class Helpers
    {
        public static string ToJsonString(this InputType input)
        {
            var entries = input.Select((kv, _) => $"\"{kv.Key}\":{kv.Value.ToJsonString()}");
            return "{" + string.Join(",", entries) + "}";
        }

        public static string ToJsonString(this IList<string> values)
        {
            return "[" + string.Join(",", values.Select(x => $"\"{x}\"")) + "]";
        }
    }
}