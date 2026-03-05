using System;
using Adguard.Dns.Api.SystemDnsModifier;
using Adguard.Dns.Provider;
using NUnit.Framework;
// ReSharper disable LocalizableElement

namespace Adguard.Dns.Tests.TestApi
{
    [TestFixture]
    public class TestSystemDnsModifierHelper
    {
	    private DnsLibsDllProvider m_DnsLibsDllProvider;

		[OneTimeSetUp]
	    public void SetUp()
	    {
		    m_DnsLibsDllProvider = (DnsLibsDllProvider)DnsLibsDllProvider.Instance;
	    }

	    [OneTimeTearDown]
	    public void TearDown()
	    {
		    m_DnsLibsDllProvider.Dispose();
	    }

		[Test]
        public void TestGetPreferredAdapterGuid()
        {
            string guid = SystemDnsModifierHelper.GetPreferredAdapterGuid();
            Assert.IsNotNull(guid);
            Assert.IsNotEmpty(guid);
            Console.WriteLine("Preferred adapter GUID: {0}", guid);
        }

        [Test]
        public void TestGetIfNameserver()
        {
            string guid = SystemDnsModifierHelper.GetPreferredAdapterGuid();
            Assert.IsNotNull(guid, "Cannot get preferred adapter GUID");
            string nameserverV4 = SystemDnsModifierHelper.GetIfNameserver(guid, false);
            Console.WriteLine("IPv4 nameserver for {0}: {1}", guid, nameserverV4 ?? "<null>");
            string nameserverV6 = SystemDnsModifierHelper.GetIfNameserver(guid, true);
            Console.WriteLine("IPv6 nameserver for {0}: {1}", guid, nameserverV6 ?? "<null>");
        }

        [Test]
        public void TestGetIfNameserverWithInvalidGuid()
        {
            string nameserver = SystemDnsModifierHelper.GetIfNameserver("{00000000-0000-0000-0000-000000000000}", false);
            Assert.IsNull(nameserver);
        }

        [Test]
        public void TestSetIfNameserverAndRestore()
        {
            string guid = SystemDnsModifierHelper.GetPreferredAdapterGuid();
            Assert.IsNotNull(guid, "Cannot get preferred adapter GUID");
            string originalNameserver = SystemDnsModifierHelper.GetIfNameserver(guid, false);
            Console.WriteLine("Original IPv4 nameserver for {0}: {1}", guid, originalNameserver ?? "<null>");
            try
            {
                uint setResult = SystemDnsModifierHelper.SetIfNameserver("8.8.8.8,8.8.4.4", guid, false);
                Assert.AreEqual(0u, setResult, "Failed to set nameserver, error code: {0}", setResult);
                string updatedNameserver = SystemDnsModifierHelper.GetIfNameserver(guid, false);
                Assert.IsNotNull(updatedNameserver);
                Assert.AreEqual("8.8.8.8,8.8.4.4", updatedNameserver);
                Console.WriteLine("Updated IPv4 nameserver for {0}: {1}", guid, updatedNameserver);
            }
            finally
            {
                uint restoreResult = SystemDnsModifierHelper.SetIfNameserver(
                    originalNameserver ?? "",
                    guid,
                    false);
                Assert.AreEqual(0u, restoreResult, "Failed to restore nameserver, error code: {0}", restoreResult);
                Console.WriteLine("Restored IPv4 nameserver for {0}", guid);
            }
        }

        [Test]
        public void TestSetIfNameserverAutomatic()
        {
            string guid = SystemDnsModifierHelper.GetPreferredAdapterGuid();
            Assert.IsNotNull(guid, "Cannot get preferred adapter GUID");
            string originalNameserver = SystemDnsModifierHelper.GetIfNameserver(guid, false);
            try
            {
                uint result = SystemDnsModifierHelper.SetIfNameserver("", guid, false);
                Assert.AreEqual(0u, result, "Failed to set nameserver to automatic, error code: {0}", result);
            }
            finally
            {
                SystemDnsModifierHelper.SetIfNameserver(
                    originalNameserver ?? "",
                    guid,
                    false);
            }
        }

        [Test]
        public void TestWfpFirewallInitAndDeinit()
        {
            IntPtr pFw = SystemDnsModifierHelper.WfpFirewallInit("TestFirewall", 0);
            Assert.AreNotEqual(IntPtr.Zero, pFw, "Failed to initialize WFP firewall");
            try
            {
                Console.WriteLine("WFP firewall initialized successfully");
            }
            finally
            {
                SystemDnsModifierHelper.WfpFirewallDeinit(pFw);
                Console.WriteLine("WFP firewall deinitialized successfully");
            }
        }

        [Test]
        [Ignore("Requires elevated privileges to run WFP transactions")]
        public void TestWfpFirewallRestrictDnsTo()
        {
            IntPtr pFw = SystemDnsModifierHelper.WfpFirewallInit("TestFirewallRestrict", 0);
            Assert.AreNotEqual(IntPtr.Zero, pFw, "Failed to initialize WFP firewall");
            try
            {
                string error = SystemDnsModifierHelper.WfpFirewallRestrictDnsTo(
                    pFw,
                    "127.0.0.1/32",
                    "::1/128");
                Assert.IsNull(error, "WFP firewall restrict DNS failed: {0}", error);
                Console.WriteLine("WFP firewall DNS restriction applied successfully");
            }
            finally
            {
                SystemDnsModifierHelper.WfpFirewallDeinit(pFw);
            }
        }

        [Test]
        [Ignore("Requires elevated privileges to run WFP transactions")]
        public void TestWfpFirewallDeinitRevertsRestrictions()
        {
            IntPtr pFw = SystemDnsModifierHelper.WfpFirewallInit("TestFirewallRevert", 0);
            Assert.AreNotEqual(IntPtr.Zero, pFw, "Failed to initialize WFP firewall");

            string error = SystemDnsModifierHelper.WfpFirewallRestrictDnsTo(
                pFw,
                "127.0.0.1/32",
                "::1/128");
            Assert.IsNull(error, "WFP firewall restrict DNS failed: {0}", error);
            Assert.DoesNotThrow(() => SystemDnsModifierHelper.WfpFirewallDeinit(pFw));
            Console.WriteLine("WFP firewall deinitialized and restrictions reverted successfully");
        }
    }
}
