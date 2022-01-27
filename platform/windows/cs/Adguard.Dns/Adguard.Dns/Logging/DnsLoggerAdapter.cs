using System;
using System.Collections.Generic;
using Adguard.Dns.Exceptions;
using AdGuard.Utils.Interop;
using AdGuard.Utils.Logging;

namespace Adguard.Dns.Logging
{
    /// <summary>
    /// Listens to logging messages of the CoreLibs and logs it with <see cref="AdGuard.Utils.Logging.Logger"/> (with
    /// </summary>
    internal static class DnsLoggerAdapter
    {
        private delegate void LogBylogLevel(string message, params object[] args);

        private static readonly Dictionary<AGDnsApi.ag_log_level, LogBylogLevel> LOG_LEVELS_MAPPING =
            new Dictionary<AGDnsApi.ag_log_level, LogBylogLevel>
            {
                {AGDnsApi.ag_log_level.AGLL_ERR, Logger.Error},
                {AGDnsApi.ag_log_level.AGLL_WARN, Logger.Warn},
                {AGDnsApi.ag_log_level.AGLL_INFO, Logger.Info},
                {AGDnsApi.ag_log_level.AGLL_TRACE, Logger.Trace},
                {AGDnsApi.ag_log_level.AGLL_DEBUG, Logger.Verbose}
            };

        private static AGDnsApi.cbd_logger_callback_t m_LoggerCallback;
        private static AGDnsApi.ag_log_level m_LoggerLogLevel;
        private static readonly object SYNC_ROOT = new object();

        /// <summary>
        /// Initializes the <see cref="DnsLoggerAdapter"/>
        /// with the specified log level
        /// </summary>
        /// <param name="logLevel">Log level you'd like to use</param>
        internal static void Init(AGDnsApi.ag_log_level logLevel)
        {
            lock (SYNC_ROOT)
            {
                Logger.Info(
                    "Initializing the DnsLoggerAdapter with level = {0}", logLevel);
                m_LoggerLogLevel = logLevel;

                if (m_LoggerCallback != null)
                {
                    return;
                }

                m_LoggerCallback = AGOnDnsLogged;
            }
        }

        /// <summary>
        /// Sets the previously initialized logger for the specified Dll
        /// </summary>
        internal static void SetLogger()
        {
            lock (SYNC_ROOT)
            {

                AGDnsApi.ag_set_log_level(m_LoggerLogLevel);
                if (m_LoggerCallback == null)
                {
                    Logger.Warn("Logger callback hasn't been initialized before");
                    return;
                }

                AGDnsApi.ag_set_log_callback(m_LoggerCallback, IntPtr.Zero);
                Logger.Info("Logger callback has been set successfully");
            }
        }

        /// <summary>
        /// This method is called from the CoreLibs and passed to managed code
        /// </summary>
        /// <param name="attachment">Pointer to the native logger</param>
        /// <param name="logLevel">Log level</param>
        /// <param name="pMessage">Pointer to the log message</param>
        /// <param name="length">Message length</param>
        private static void AGOnDnsLogged(
            IntPtr attachment,
            AGDnsApi.ag_log_level logLevel,
            IntPtr pMessage,
            UInt32 length)
        {
            try
            {
                LogBylogLevel logByLogLevel = LOG_LEVELS_MAPPING[logLevel];
                MarshalUtils.ag_buffer agBuffer = new MarshalUtils.ag_buffer
                {
                    data = pMessage,
                    size = length
                };

                string message = MarshalUtils.AgBufferToString(agBuffer);
                // We have to forcibly trim trailing CR due to
                // https://bit.adguard.com/projects/ADGUARD-CORE-LIBS/repos/dns-libs/pull-requests/306/diff#platform/windows/capi/include/ag_dns.h
                message = message.TrimEnd(Environment.NewLine.ToCharArray());
                logByLogLevel(message);
            }
            catch (Exception ex)
            {
                DnsExceptionHandler.HandleManagedException(ex);
            }
        }

        // Avoid the closure allocation, see https://gist.github.com/AArnott/d285feef75c18f6ecd2b
        private static Func<T> AsFunc<T>(this T value) where T : class
        {
            return value.Return;
        }

        private static T Return<T>(this T value)
        {
            return value;
        }
    }
}