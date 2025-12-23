using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Exceptions;
using Adguard.Dns.Helpers;
using AdGuard.Utils.Base.Interop;
using AdGuard.Utils.Base.Logging;
using static Adguard.Dns.AGDnsApi;

namespace Adguard.Dns.DnsProxyServer
{
    // ReSharper disable InconsistentNaming
    public class DnsProxyServer : IDnsProxyServer, IDisposable
    {
        private IntPtr m_pCallbackConfigurationC;
        private IntPtr m_pProxyServer;

        // ReSharper disable once PrivateFieldCanBeConvertedToLocalVariable
        // We shouldn't make this variable local (within the DnsProxyServer ctor) to protect it from the GC
        private AGDnsProxyServerCallbacks m_callbackConfigurationC;
        private bool m_IsStarted;
        private readonly object m_SyncRoot = new object();
        private readonly DnsProxySettings m_DnsProxySettings;
        private readonly IDnsProxyServerCallbackConfiguration m_CallbackConfiguration;

        private uint m_DnsMessageHandlerNextId = 0;
        private readonly Dictionary<uint, ag_handle_message_async_cb> m_DnsMessageHandlers =
	        new Dictionary<uint, ag_handle_message_async_cb>();

		/// <summary>
		/// Initializes the new instance of the DnsProxyServer
		/// </summary>
		/// <param name="dnsProxySettings">Dns proxy settings
		/// (<seealso cref="DnsProxySettings"/>)</param>
		/// <param name="callbackConfiguration">Callback config configuration
		/// (<seealso cref="IDnsProxyServerCallbackConfiguration"/>)</param>
		/// <exception cref="NotSupportedException">Thrown if current API version is not supported</exception>
		public DnsProxyServer(
            DnsProxySettings dnsProxySettings,
            IDnsProxyServerCallbackConfiguration callbackConfiguration)
        {
            lock (m_SyncRoot)
            {
                Logger.Info("Creating the DnsProxyServer");
                ValidateApi();
                m_DnsProxySettings = dnsProxySettings;
                m_CallbackConfiguration = callbackConfiguration;
            }
        }

        #region IDnsProxyServer members

        /// <summary>
        /// Starts the proxy server
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot starting the proxy server
        /// for any reason</exception>
        public void Start()
        {
            lock (m_SyncRoot)
            {
                Logger.Info("Starting the DnsProxyServer");
                if (IsStarted)
                {
                    Logger.Info("DnsProxyServer is already started, doing nothing");
                    return;
                }

                Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
                IntPtr ppOutMessage = IntPtr.Zero;
                IntPtr pOutMessage = IntPtr.Zero;
                IntPtr pOutResult = IntPtr.Zero;
                try
                {
                    ag_dnsproxy_settings dnsProxySettingsC =
                        DnsApiConverter.ToNativeObject(m_DnsProxySettings, allocatedPointers);
                    m_callbackConfigurationC = DnsApiConverter.ToNativeObject(m_CallbackConfiguration, this);

                    IntPtr pDnsProxySettingsC = MarshalUtils.StructureToPtr(dnsProxySettingsC, allocatedPointers);
                    m_pCallbackConfigurationC = MarshalUtils.StructureToPtr(m_callbackConfigurationC);

                    pOutResult = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                    ppOutMessage = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                    m_pProxyServer = ag_dnsproxy_init(
	                    pDnsProxySettingsC,
	                    m_pCallbackConfigurationC,
	                    pOutResult,
	                    ppOutMessage);
                    ag_dnsproxy_init_result outResultEnum = ag_dnsproxy_init_result.AGDPIR_OK;
                    if (m_pProxyServer == IntPtr.Zero)
                    {
                        long? outResult = MarshalUtils.ReadNullableInt(pOutResult);
                        if (outResult.HasValue)
                        {
                            outResultEnum = (ag_dnsproxy_init_result)outResult.Value;
                        }

                        pOutMessage = MarshalUtils.SafeReadIntPtr(ppOutMessage);
                        string outMessage = MarshalUtils.PtrToString(pOutMessage);
                        string errorMessage =
                            $"Failed to start the DnsProxyServer with the result {outResultEnum} and message {outMessage}";
                        throw new DnsProxyInitializationException(errorMessage, outResultEnum);
                    }

                    m_IsStarted = true;
                    Logger.Info("Finished starting the DnsProxyServer");
                }
                catch (DnsProxyInitializationException)
                {
                    Dispose();
                    throw;
                }
                catch (Exception ex)
                {
                    Dispose();
                    throw new InvalidOperationException("error while starting the DnsProxyServer: ", ex);
                }
                finally
                {
                    MarshalUtils.SafeFreeHGlobal(allocatedPointers);
					ag_str_free(pOutMessage);
                    MarshalUtils.SafeFreeHGlobal(ppOutMessage);
                    MarshalUtils.SafeFreeHGlobal(pOutResult);
                }
            }
        }

        /// <summary>
        /// Stops the proxy server
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// via native method</exception>
        public void Stop()
        {
            lock (m_SyncRoot)
            {
                try
                {
                    Logger.Info("Stopping the DnsProxyServer");
                    if (!IsStarted)
                    {
                        Logger.Info("DnsProxyServer is not started, doing nothing");
                        return;
                    }

					ag_dnsproxy_deinit( 
						m_pProxyServer);
                    m_IsStarted = false;
                    Logger.Info("Finished stopping the DnsProxyServer");
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("error while stopping the DnsProxyServer: {0}", ex);
                }
                finally
                {
                    Dispose();
                }
            }
        }

        /// <summary>
        /// Gets the current DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the current dns proxy settings via native method</exception>
        public DnsProxySettings GetCurrentDnsProxySettings()
        {
            Logger.Info("Get current DnsProxyServer settings");
            lock (m_SyncRoot)
            {
                if (!IsStarted)
                {
                    Logger.Info("DnsProxyServer is not started, doing nothing");
                    return null;
                }

                IntPtr pSettings = ag_dnsproxy_get_settings( 
	                m_pProxyServer);
                DnsProxySettings currentDnsProxySettings =
                    GetDnsProxySettings(pSettings);
                return currentDnsProxySettings;
            }
        }

        /// <summary>
        /// Gets the default DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the default dns proxy settings via native method</exception>
        public static DnsProxySettings GetDefaultDnsProxySettings()
        {
            Logger.Info("Get default DnsProxyServer settings");
            IntPtr pSettings = ag_dnsproxy_settings_get_default();
            DnsProxySettings defaultDnsProxySettings =
                GetDnsProxySettings(pSettings);
            return defaultDnsProxySettings;
        }

        /// <summary>
        /// Gets the DNS proxy settings,
        /// according to the specified <see cref="pCurrentDnsProxySettings"/>
        /// </summary>
        /// <param name="pCurrentDnsProxySettings">DNS proxy settings
        /// (<seealso cref="Func{TResult}"/>)</param>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the DNS proxy settings via native method</exception>
        /// <returns>The <see cref="DnsProxySettings"/> object</returns>
        private static DnsProxySettings GetDnsProxySettings(IntPtr pCurrentDnsProxySettings)
        {
            Logger.Info("Get DNS proxy settings settings");
            if (pCurrentDnsProxySettings == IntPtr.Zero)
            {
                throw new InvalidOperationException("Cannot get the DNS proxy settings");
            }

            DnsProxySettings currentDnsProxySettings =
                MarshalUtils.PtrToClass<DnsProxySettings, ag_dnsproxy_settings>(
                    pCurrentDnsProxySettings,
                    DnsApiConverter.FromNativeObject);
            Logger.Info("Finished getting the DNS proxy settings");
            return currentDnsProxySettings;
        }

        /// <summary>
        /// The DnsProxyServer status
        /// Determines, whether the current instance of the proxy server is started
        /// </summary>
        public bool IsStarted
        {
            get
            {
                lock (m_SyncRoot)
                {
                    return m_IsStarted;
                }
            }
        }

        /// <summary>
        /// Process a DNS message and return the response.
        /// </summary>
        /// <param name="message">A DNS message in wire format </param>
        /// <param name="info">Additional parameters</param>
        /// <returns>The DNS response in wire format</returns>
		public byte[] HandleDnsMessage(byte[] message, DnsMessageInfo info)
        {
	        MarshalUtils.ag_buffer messageBuffer = MarshalUtils.BytesToAgBuffer(message);
	        ag_dns_message_info nativeDnsMessageInfo = DnsApiConverter.ToNativeObject(info);
	        IntPtr pNativeDnsMessageInfo = MarshalUtils.StructureToPtr(nativeDnsMessageInfo);
			MarshalUtils.ag_buffer dnsMessageResult =
				ag_dnsproxy_handle_message(m_pProxyServer, messageBuffer, pNativeDnsMessageInfo);
			byte[] dnsMessageResultBytes = MarshalUtils.AgBufferToBytes(dnsMessageResult);
			ag_buffer_free(dnsMessageResult);
			return dnsMessageResultBytes;
        }

		/// <summary>
		/// Process a DNS message and call `handler` on an unspecified thread with the response.
		/// </summary>
		/// <param name="message">A DNS message in wire format</param>
		/// <param name="info">Additional parameters</param>
		/// <param name="handler">Callback function for asynchronous message processing.</param>
		public void HandleDnsMessageAsync(byte[] message, DnsMessageInfo info, Action<byte[]> handler)
        {
			// Here, a local function would use a closure and could not be a static instance.
			// In theory, it would be collected by the GC before the request is finished,
			// or there would be a memory leak for each request.
			// So, we instantiate each delegate and save it until manual execution.
			uint handlerId = m_DnsMessageHandlerNextId++;
	        ag_handle_message_async_cb nativeMessageHandler = pBuffer =>
			{
				byte[] bufferBytes = MarshalUtils.AgBufferPtrToBytes(pBuffer);
				handler(bufferBytes);
				lock (m_DnsMessageHandlers)
				{
					m_DnsMessageHandlers.Remove(handlerId);
				}
			};

	        lock (m_DnsMessageHandlers)
	        {
		        m_DnsMessageHandlers[handlerId] = nativeMessageHandler;
	        }

			MarshalUtils.ag_buffer messageBuffer = MarshalUtils.BytesToAgBuffer(message);
			ag_dns_message_info nativeDnsMessageInfo = DnsApiConverter.ToNativeObject(info);
			IntPtr pNativeDnsMessageInfo = MarshalUtils.StructureToPtr(nativeDnsMessageInfo);
			ag_dnsproxy_handle_message_async(
				m_pProxyServer,
				messageBuffer,
				pNativeDnsMessageInfo,
				nativeMessageHandler);
        }
        
                /// <summary>
        ///  Reapply DNS proxy settings with optional filter reloading.
        /// </summary>
        /// <param name="dnsProxySettings">dnsProxySettings</param>
        /// <param name="reapplyFilters">if true, DNS filters will be reloaded from settings.
        /// If false, existing filters are preserved (fast update).</param>
        /// <param name="outResultEnum">Result enum</param>
        public bool ReapplySettings(
            DnsProxySettings dnsProxySettings, bool reapplyFilters, out ag_dnsproxy_init_result outResultEnum)
        {
            Logger.InfoBeforeCall();
            lock (m_SyncRoot)
            {
                if (m_pProxyServer == IntPtr.Zero)
                {
                    Logger.Info("Cannot reapply settings as the inner proxy server is not specified yet");
                    outResultEnum = ag_dnsproxy_init_result.AGDPIR_PROXY_NOT_SET;
                    return false;
                }
            
                Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
                IntPtr pOutResult = IntPtr.Zero;
                IntPtr ppOutMessage = IntPtr.Zero;
                IntPtr pOutMessage = IntPtr.Zero;
                try
                {
                    ag_dnsproxy_settings dnsProxySettingsC =
                        DnsApiConverter.ToNativeObject(dnsProxySettings, allocatedPointers);
                    IntPtr pDnsProxySettingsC = MarshalUtils.StructureToPtr(dnsProxySettingsC, allocatedPointers);
                    pOutResult = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                    ppOutMessage = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                    bool result = ag_dnsproxy_reapply_settings(
                        m_pProxyServer,
                        pDnsProxySettingsC,
                        reapplyFilters,
                        pOutResult,
                        ppOutMessage);
                    outResultEnum = ag_dnsproxy_init_result.AGDPIR_OK;
                    long? outResult = MarshalUtils.ReadNullableInt(pOutResult);
                    if (outResult.HasValue)
                    {
                        outResultEnum = (ag_dnsproxy_init_result)outResult.Value;
                    }

                    pOutMessage = MarshalUtils.SafeReadIntPtr(ppOutMessage);
                    string outMessage = MarshalUtils.PtrToString(pOutMessage);
                    Logger.Info("Reapplying settings completed with the result {0} ({1}, {2})",
                        result,
                        outResultEnum,
                        outMessage);
                    return result;
                }
                finally
                {
                    MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                    ag_str_free(pOutMessage);
                    MarshalUtils.SafeFreeHGlobal(pOutResult);
                    MarshalUtils.SafeFreeHGlobal(ppOutMessage);
                }
            }
        }

		#endregion

		public void Dispose()
        {
            lock (m_SyncRoot)
            {
                if (m_pCallbackConfigurationC == IntPtr.Zero)
                {
                    return;
                }

                MarshalUtils.SafeFreeHGlobal(m_pCallbackConfigurationC);
                m_pCallbackConfigurationC = IntPtr.Zero;
            }
        }
    }
}
