using System;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Api.FilteringLogAction;
using AdGuard.Utils.Json;
using AdGuard.Utils.Logging;
using AdGuard.Utils.Threading;
using Newtonsoft.Json;

namespace Adguard.Dns.TestApp
{
    public class DnsProxyServerCallbackConfiguration : IDnsProxyServerCallbackConfiguration
    {
        public void OnDnsRequestProcessed(object sender, DnsRequestProcessedEventArgs args)
        {
            Logger.Info("OnDnsRequestProcessed called, args - {0}",
                JsonConvert.SerializeObject(args, Formatting.Indented));
            FastThreadPool.SubmitTask(() =>
            {
                using (FilteringLogRuleGenerator filteringLogRuleGenerator = new FilteringLogRuleGenerator(args))
                {
                    FilteringLogAction filteringLogAction = filteringLogRuleGenerator.GetFilteringLogAction();
                    if (filteringLogAction == null)
                    {
                        return;
                    }

                    AGDnsApi.ag_rule_generation_options[] possibleOptions =
                    {
                        filteringLogAction.RequiredOptions,
                        filteringLogAction.AllowedOptions
                    };

                    foreach (string ruleTemplate in filteringLogAction.RuleTemplates)
                    {
                        foreach (AGDnsApi.ag_rule_generation_options options in possibleOptions)
                        {
                            string rule = filteringLogRuleGenerator.GenerateRuleFromTemplate(
                                ruleTemplate,
                                options);
                            Logger.Info("Generated rule is {0}. Generation options were : {1}", rule, options);
                        }
                    }
                }
            });
        }
    }
}