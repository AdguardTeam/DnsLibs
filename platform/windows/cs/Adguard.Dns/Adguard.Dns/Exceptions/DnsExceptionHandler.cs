using System;
using System.Runtime.InteropServices;

namespace Adguard.Dns.Exceptions
{
    public static class DnsExceptionHandler
    {
        // We shouldn't make this variable local
        // to protect it from the GC
        private static cbd_unhandled_native_exception_filter_t m_UnhandledNativeExceptionFilterCallback;
        private static Func<Exception, bool> m_UnhandledManagedExceptionCallback;
        private static IUnhandledExceptionConfiguration m_UnhandledExceptionConfiguration;
        private static readonly object SYNC_ROOT = new object();

        /// <summary>
        /// Delegate for native crashes.
        /// </summary>
        /// <param name="pException">Pointer to original crash</param>
        /// <returns>see https://msdn.microsoft.com/ru-RU/library/windows/desktop/ms681401(v=vs.85).aspx</returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        // ReSharper disable once InconsistentNaming
        internal delegate uint cbd_unhandled_native_exception_filter_t(IntPtr pException);

        /// <summary>
        /// Initializes the <see cref="DnsExceptionHandler"/> with
        /// the specified <see cref="unhandledExceptionConfiguration"/>
        /// </summary>
        /// <param name="unhandledExceptionConfiguration">Callbacks
        /// for handling the managed and native unhandled exceptions
        /// (<seealso cref="IUnhandledExceptionConfiguration"/>)</param>
        public static void Init(IUnhandledExceptionConfiguration unhandledExceptionConfiguration)
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
        public static void SetUnhandledExceptionConfiguration()
        {
            lock (SYNC_ROOT)
            {
                AGDnsApi.ag_enable_SetUnhandledExceptionFilter();
                SetUnhandledExceptionFilter(m_UnhandledNativeExceptionFilterCallback);
                AGDnsApi.ag_disable_SetUnhandledExceptionFilter();
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
        /// Sets delegate <see cref="cbd_unhandled_native_exception_filter_t" />
        /// for native crashes.
        /// </summary> <param name="callback">Callback delegate
        /// (<seealso cref="cbd_unhandled_native_exception_filter_t"/>)</param>
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr SetUnhandledExceptionFilter(
            [MarshalAs(UnmanagedType.FunctionPtr)]
            cbd_unhandled_native_exception_filter_t callback);
    }
}