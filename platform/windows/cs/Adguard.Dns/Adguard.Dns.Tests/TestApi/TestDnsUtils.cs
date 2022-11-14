using System;
using System.Collections.Generic;
using Adguard.Dns.Utils;
using NUnit.Framework;

namespace Adguard.Dns.Tests.TestApi
{
    [TestFixture]
    public class TestDnsUtils
    {
        [Test]
        public void TesRuleValidation()
        {
            Dictionary<string, bool> ruleValidationTable = new Dictionary<string, bool>
            {
                {"||browser.events.data.microsoft.com^$dnstype=~A", true}
            };

            foreach (var pair in ruleValidationTable)
            {
                Console.WriteLine("Rule: {0}", pair.Key);
                Assert.AreEqual(DnsUtils.IsRuleValid(pair.Key), pair.Value);
            }
        }
    }
}