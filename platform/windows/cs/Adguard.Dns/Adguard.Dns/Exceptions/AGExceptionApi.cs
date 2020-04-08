using System;
using System.Runtime.InteropServices;
using Adguard.Dns.Helpers;
using Adguard.Dns.Logging;

// ReSharper disable InconsistentNaming

namespace Adguard.Dns.Exceptions
{
    /// <summary>
    /// Logging adapter.
    /// The purpose of this class is to pass logging from the native code to managed
    /// so that we could use our managed logger implementation
    /// </summary>
    internal class AGExceptionApi
    {
        private static readonly ILog LOG = LogProvider.For<AGExceptionApi>();
        private const string ENABLE_SET_UNHANDLED_EXCEPTION_FILTER_FUNCTION_NAME =
            "AGExceptionUtils_enableSetUnhandledExceptionFilter";
        private const string DISABLE_SET_UNHANDLED_EXCEPTION_FILTER_FUNCTION_NAME =
            "AGExceptionUtils_disableSetUnhandledExceptionFilter";

        /// <summary>
        /// Delegate for native crashes.
        /// </summary>
        /// <param name="pException">Pointer to original crash</param>
        /// <returns>see https://msdn.microsoft.com/ru-RU/library/windows/desktop/ms681401(v=vs.85).aspx</returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        // ReSharper disable once InconsistentNaming
        internal delegate uint cbd_unhandled_native_exception_filter_t(IntPtr pException);

        /// <summary>
        /// Disables SetUnhandledExceptionFilter function which used to modify unhandled exception handler
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void DisableSetUnhandledExceptionFilterDelegate();

        /// <summary>
        /// Enables SetUnhandledExceptionFilter function which used to modify unhandled exception handler
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void EnableSetUnhandledExceptionFilterDelegate();

        /// <summary>
        /// Gets ot sets the function,
        /// that disables "SetUnhandledExceptionFilter" function which used to modify unhandled exception handler
        /// (<seealso cref="DisableSetUnhandledExceptionFilterDelegate"/>)
        /// </summary>
        internal DisableSetUnhandledExceptionFilterDelegate DisableSetUnhandledExceptionFilter { get; private set; }

        /// <summary>
        /// Gets ot sets the function,
        /// that enables SetUnhandledExceptionFilter function which used to modify unhandled exception handler
        /// (<seealso cref="EnableSetUnhandledExceptionFilterDelegate"/>)
        /// </summary>
        internal EnableSetUnhandledExceptionFilterDelegate EnableSetUnhandledExceptionFilter { get; private set; }

        internal AGExceptionApi(string dllName)
        {
            LOG.InfoFormat("Start initializing the AGExceptionApi for dll \"{0}\"", dllName);
            DynamicDllFunctions dllFunctions = new DynamicDllFunctions(dllName);
            EnableSetUnhandledExceptionFilter =
                dllFunctions.GetDelegate<EnableSetUnhandledExceptionFilterDelegate>(
                    ENABLE_SET_UNHANDLED_EXCEPTION_FILTER_FUNCTION_NAME);

            DisableSetUnhandledExceptionFilter =
                dllFunctions.GetDelegate<DisableSetUnhandledExceptionFilterDelegate>(
                    DISABLE_SET_UNHANDLED_EXCEPTION_FILTER_FUNCTION_NAME);
            LOG.Info("The AGExceptionApi has been initialized successfully");
        }
    }
}