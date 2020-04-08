using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Adguard.Dns.Exceptions
{
    public static class CoreExceptionHandler
    {
        // We shouldn't make this variable local (within the SetNativeCrashCallback method)
        // to protect it from the GC
        private static AGExceptionApi.cbd_unhandled_native_exception_filter_t m_UnhandledNativeExceptionFilterCallback;
        private static Func<Exception, bool> m_UnhandledManagedExceptionCallback;
        private static readonly Dictionary<string, AGExceptionApi> AG_EXCEPTION_APIS =
            new Dictionary<string, AGExceptionApi>();
        private static IUnhandledExceptionConfiguration m_UnhandledExceptionConfiguration;
        private static readonly object SYNC_ROOT = new object();

        /// <summary>
        /// Initializes the <see cref="CoreExceptionHandler"/> with
        /// the specified <see cref="unhandledExceptionConfiguration"/>
        /// </summary>
        /// <param name="unhandledExceptionConfiguration">Callbacks
        /// for handling the managed and native unhandled exceptions
        /// (<seealso cref="IUnhandledExceptionConfiguration"/>)</param>
        internal static void Init(IUnhandledExceptionConfiguration unhandledExceptionConfiguration)
        {
            lock (SYNC_ROOT)
            {
                m_UnhandledExceptionConfiguration = unhandledExceptionConfiguration;
                if (unhandledExceptionConfiguration == null)
                {
                    return;
                }

                UnhandledExceptionCallbackAdapter unhandledExceptionCallbackAdapter =
                    new UnhandledExceptionCallbackAdapter(m_UnhandledExceptionConfiguration);

                m_UnhandledNativeExceptionFilterCallback =
                    unhandledExceptionCallbackAdapter.OnUnhandledNativeExceptionFilter;
                m_UnhandledManagedExceptionCallback =
                    unhandledExceptionCallbackAdapter.OnUnhandledManagedException;
            }
        }

        /// <summary>
        /// Sets an stored unhandled exception configuration for the specified Dll
        /// </summary>
        /// <param name="dllName">Dll name, foe which we need to set unhandled exception configuration</param>
        internal static void SetUnhandledExceptionConfiguration(string dllName)
        {
            lock (SYNC_ROOT)
            {
                AGExceptionApi agExceptionApi;
                if (!AG_EXCEPTION_APIS.TryGetValue(dllName, out agExceptionApi))
                {
                    agExceptionApi = new AGExceptionApi(dllName);
                    AG_EXCEPTION_APIS.Add(dllName, agExceptionApi);
                }

                if (m_UnhandledExceptionConfiguration == null)
                {
                    agExceptionApi.EnableSetUnhandledExceptionFilter();
                    SetUnhandledExceptionFilter(null);
                    m_UnhandledNativeExceptionFilterCallback = null;
                    m_UnhandledManagedExceptionCallback = null;
                    return;
                }

                SetUnhandledExceptionFilter(m_UnhandledNativeExceptionFilterCallback);
                agExceptionApi.DisableSetUnhandledExceptionFilter();
            }
        }

        /// <summary>
        /// Handles the managed exception,
        /// in fact invokes the callback for handling managed exception,
        /// i.e. this method is the wrapper around the
        /// <see cref="IUnhandledExceptionConfiguration.OnUnhandledManagedException"/>
        /// (<seealso cref="Exception"/>)
        /// Note, that the inner exception callback implementation
        /// (<see cref="IUnhandledExceptionConfiguration.OnUnhandledManagedException"/>)
        /// determines, whether the specified <see cref="exception"/> should be re-thrown.
        /// </summary>
        /// <param name="exception">Exception to handle
        /// (<seealso cref="Exception"/>)</param>
        internal static void HandleManagedException(Exception exception)
        {
            if (m_UnhandledManagedExceptionCallback == null)
            {
                throw exception;
            }

            bool isNeedToReThrown = m_UnhandledManagedExceptionCallback(exception);
            if (isNeedToReThrown)
            {
                throw exception;
            }
        }

        /// <summary>
        /// Sets delegate <see cref="AGExceptionApi.cbd_unhandled_native_exception_filter_t" />
        /// for native crashes.
        /// </summary>
        /// <param name="callback">Callback delegate
        /// (<seealso cref="AGExceptionApi.cbd_unhandled_native_exception_filter_t"/>)</param>
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr SetUnhandledExceptionFilter(
            [MarshalAs(UnmanagedType.FunctionPtr)]
            AGExceptionApi.cbd_unhandled_native_exception_filter_t callback);
    }
}