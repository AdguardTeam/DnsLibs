using System.IO;
using System.Linq;
using System.Text;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Helper methods for <see cref="Adguard.Dns.Api.DnsProxyServer.Configs.FilterParams"/>
    /// </summary>
    public static class FilterParamsHelper
    {
        /// <summary>
        /// Gets concatenated lines from file on <param name="path"/> without line breaks
        /// </summary>
        /// <param name="path">Path to file</param>
        /// <returns>Concatenated lines</returns>
        public static string GetStringRulesFromFile(string path)
        {
            string[] rules = File.ReadAllLines(path);
            string res = rules.Aggregate(
                new StringBuilder(),
                (sb, rule) => sb.Append(rule),
                sb => sb.ToString());
            return res;
        }
    }
}