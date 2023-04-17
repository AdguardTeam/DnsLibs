using System;
using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Helpers;
using AdGuard.Utils.Adapters.Interop;
using AdGuard.Utils.Adapters.Logging;

namespace Adguard.Dns.Api.FilteringLogAction
{
    /// <summary>
    /// Rule generator for creating rules from <see cref="DnsRequestProcessedEventArgs"/>.
    /// Used for filtering log suggested rules.
    /// </summary>
    public class FilteringLogRuleGenerator : IFilteringLogRuleGenerator
    {
        private readonly DnsRequestProcessedEventArgs m_EventArgs;
        private readonly Queue<IntPtr> m_AllocatedPointers;

        private readonly IntPtr m_PEventArgs;

        /// <summary>
        /// Initializes a new instance of <see cref="FilteringLogRuleGenerator"/>
        /// </summary>
        /// <param name="eventArgs">The dns request processed event args.</param>
        public FilteringLogRuleGenerator(DnsRequestProcessedEventArgs eventArgs)
        {
            m_EventArgs = eventArgs;
            m_AllocatedPointers = new Queue<IntPtr>();
            AGDnsApi.ag_dns_request_processed_event eventArgsC 
                = DnsApiConverter.ToNativeObject(eventArgs, m_AllocatedPointers);
            m_PEventArgs = MarshalUtils.StructureToPtr(eventArgsC, m_AllocatedPointers);
        }

        /// <summary>
        /// Gets the filtering log action.
        /// </summary>
        /// <returns>The filtering log action if succeded, <c>null</c> otherwise.</returns>
        public FilteringLogAction GetFilteringLogAction()
        {
            IntPtr pAction = AGDnsApi.ag_dns_filtering_log_action_from_event(m_PEventArgs);
            if (pAction == IntPtr.Zero)
            {
                Logger.Verbose(
                    "Cannot obtain filtering log actions for request. Domain - {0})",
                    m_EventArgs.Domain);

                return null;
            }

            AGDnsApi.ag_dns_filtering_log_action actionC =
                MarshalUtils.PtrToStructure<AGDnsApi.ag_dns_filtering_log_action>(pAction);
            FilteringLogAction action = DnsApiConverter.FromNativeObject(actionC);
            return action;
        }

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
        public string GenerateRuleFromTemplate(
            string ruleTemplate,
            AGDnsApi.ag_rule_generation_options generationOptions)
        {
            if (string.IsNullOrEmpty(ruleTemplate))
            {
                throw new ArgumentException(nameof(ruleTemplate));
            }

            IntPtr pResult = AGDnsApi.ag_dns_generate_rule_with_options(ruleTemplate, m_PEventArgs, generationOptions);
            if (pResult == IntPtr.Zero)
            {
                throw new InvalidOperationException("Cannot generate rule");
            }

            string result = MarshalUtils.PtrToString(pResult);
            return result;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            MarshalUtils.SafeFreeHGlobal(m_AllocatedPointers);
        }
    }
}