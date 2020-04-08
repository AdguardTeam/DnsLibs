using System;

namespace Adguard.Dns.Exceptions
{
    /// <summary>
    /// Configuration for unhandled native and managed exception callbacks
    /// </summary>
    public interface IUnhandledExceptionConfiguration
    {
        /// <summary>
        /// Called when need to handle a pure native exception
        /// </summary>
        /// <param name="pException">The pointer to the native exception to handle</param>
        void OnUnhandledNativeExceptionFilter(IntPtr pException);

        /// <summary>
        /// Called when need to handle a managed exception
        /// </summary>
        /// <param name="exception">Exception to handle managed
        /// (<seealso cref="Exception"/>)</param>
        /// <returns>True, if the specified <see cref="exception"/> should be re-thrown,
        /// otherwise - false</returns>
        bool OnUnhandledManagedException(Exception exception);
    }
}