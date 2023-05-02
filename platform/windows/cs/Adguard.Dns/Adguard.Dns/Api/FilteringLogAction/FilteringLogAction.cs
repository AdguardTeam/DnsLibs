using System.Collections.Generic;

namespace Adguard.Dns.Api.FilteringLogAction
{
    /// <summary>
    /// The filtering log action.
    /// Defines the various fields of an action that can be taken as a result of applying a DNS filter rule.
    /// (A managed mirror of <see cref="AGDnsApi.ag_dns_filtering_log_action"/>)
    /// </summary>
    public class FilteringLogAction
    {
        /// <summary>
        /// Gets or sets the rule templates.
        /// </summary>
        public List<string> RuleTemplates { get; set; }

        /// <summary>
        /// Gets or sets the allowed generation options.
        /// </summary>
        public AGDnsApi.ag_rule_generation_options AllowedOptions { get; set; }

        /// <summary>
        /// Gets or sets the required generation options.
        /// </summary>
        public AGDnsApi.ag_rule_generation_options RequiredOptions { get; set; }

        /// <summary>
        /// Gets or sets the value indicating whether the rule is blocking or not.
        /// </summary>
        public bool IsBlocking { get; set; }
    }
}