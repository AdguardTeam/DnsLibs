using System;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;

namespace Adguard.Dns.Api.FilteringLogAction
{
    /// <summary>
    /// Rule generator for creating rules from <see cref="DnsRequestProcessedEventArgs"/>.
    /// Used for filtering log suggested rules.
    /// </summary>
    public interface IFilteringLogRuleGenerator : IDisposable
    {
        /// <summary>
        /// Gets the filtering log action.
        /// </summary>
        /// <returns>The filtering log action if succeded, <c>null</c> otherwise.</returns>
        FilteringLogAction GetFilteringLogAction();

        /// <summary>
        /// Generates the particular filtering rule according to the passed generation options
        /// and <see cref="ruleTemplate"/>
        /// within the rule templates obtained from <see cref="FilteringLogAction.RuleTemplates"/>
        /// </summary>
        /// <param name="ruleTemplate">The rule template.</param>
        /// <param name="generationOptions">
        /// The generation options.
        /// (<seealso cref="AGDnsApi.ag_rule_generation_options"/>)
        /// </param>
        /// <returns>The generated rule.</returns>
        /// <exception cref="ArgumentException">Thrown if rule template is empty.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown, if cannot generate rule from template for any reason
        /// </exception>
        string GenerateRuleFromTemplate(
            string ruleTemplate,
            AGDnsApi.ag_rule_generation_options generationOptions);
    }
}