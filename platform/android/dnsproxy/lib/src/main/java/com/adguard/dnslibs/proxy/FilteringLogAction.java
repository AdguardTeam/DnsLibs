package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

/**
 * Contains a list of suggested rules to generate for a given filtering log event.
 */
public class FilteringLogAction {
    /**
     * Rule generation options.
     */
    public enum Option {
        /**
         * Add an $important modifier.
         */
        @SuppressWarnings("PointlessBitwiseExpression")
        IMPORTANT(1 << 0),

        /**
         * Add a $dnstype modifier.
         */
        DNSTYPE(1 << 1),

        ;

        final int value;

        Option(int value) {
            this.value = value;
        }

        static EnumSet<Option> fromValues(int union) {
            EnumSet<Option> set = EnumSet.noneOf(Option.class);
            for (Option o : values()) {
                if ((union & o.value) != 0) {
                    set.add(o);
                }
            }
            return set;
        }
    }

    /**
     * A template for rule generation. Valid until the {@link FilteringLogAction}
     * that produced this template is closed.
     */
    public static class RuleTemplate {
        private final String text;

        public RuleTemplate(String text) {
            this.text = text;
        }

        /**
         * @return A string representation of thsi template.
         */
        public String toString() {
            return text;
        }
    }

    private final List<RuleTemplate> templates;
    private final EnumSet<Option> allowedOptions;
    private final EnumSet<Option> requiredOptions;
    private final boolean blocking;

    /**
     * Used internally.
     */
    public FilteringLogAction(List<RuleTemplate> templates, int allowedOptions, int requiredOptions, boolean blocking) {
        this.templates = templates;
        this.allowedOptions = Option.fromValues(allowedOptions);
        this.requiredOptions = Option.fromValues(requiredOptions);
        this.blocking = blocking;
    }

    /**
     * @return The list of rule templates.
     */
    public List<RuleTemplate> getTemplates() {
        return new ArrayList<>(templates);
    }

    /**
     * @return The set of allowed options (see constants in {@link RuleTemplate}).
     * Specifying other options when generating a rule may result in an invalid rule.
     */
    public EnumSet<Option> getAllowedOptions() {
        return EnumSet.copyOf(allowedOptions);
    }

    /**
     * @return The set of required options (see constants in {@link RuleTemplate}).
     * Not specifying all of these options when generating a rule may result in an invalid rule.
     * You may add values to the returned set: this function returns a copy.
     */
    public EnumSet<Option> getRequiredOptions() {
        return EnumSet.copyOf(requiredOptions);
    }

    /**
     * @return Whether the rules generated from this action block something.
     */
    public boolean isBlocking() {
        return blocking;
    }
}
