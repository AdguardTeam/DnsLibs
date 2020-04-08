using System;

namespace Adguard.Dns.Exceptions
{
    /// <summary>
    /// An adapter between the native callback and the managed callback
    /// for the <see cref="IUnhandledExceptionConfiguration"/>.
    /// <seealso cref="AGExceptionApi.cbd_unhandled_native_exception_filter_t"/>
    /// </summary>
    internal class UnhandledExceptionCallbackAdapter
    {
        private readonly IUnhandledExceptionConfiguration m_UnhandledExceptionConfiguration;
        private readonly AGExceptionApi.cbd_unhandled_native_exception_filter_t m_OnUnhandledNativeExceptionFilter;
        private readonly object m_UnhandledExceptionSyncRoot = new object();

        /// <summary>
        /// Creates an instance of the adapter
        /// </summary>
        /// <param name="unhandledExceptionConfiguration">Unhandled exception callbacks configuration,
        /// which implements
        /// the <see cref="IUnhandledExceptionConfiguration"/> interface</param>
        internal UnhandledExceptionCallbackAdapter(
            IUnhandledExceptionConfiguration unhandledExceptionConfiguration)
        {
            m_UnhandledExceptionConfiguration = unhandledExceptionConfiguration;
            m_OnUnhandledNativeExceptionFilter = OnUnhandledExceptionFilter;
        }

        /// <summary>
        /// Native <see cref="AGExceptionApi.cbd_unhandled_native_exception_filter_t"/> object
        /// </summary>
        // ReSharper disable once ConvertToAutoProperty
        internal AGExceptionApi.cbd_unhandled_native_exception_filter_t OnUnhandledNativeExceptionFilter
        {
            get { return m_OnUnhandledNativeExceptionFilter; }
        }

        /// <summary>
        /// Gets the unhandled managed exception callback
        /// </summary>
        internal Func<Exception, bool> OnUnhandledManagedException
        {
            get
            {
                lock (m_UnhandledExceptionSyncRoot)
                {
                    return m_UnhandledExceptionConfiguration.OnUnhandledManagedException;
                }
            }
        }

        /// <summary>
        /// OnUnhandledExceptionFilter adapter
        /// </summary>
        /// <param name="pException">Pointer to original crash</param>
        /// <returns>https://msdn.microsoft.com/ru-RU/library/windows/desktop/ms681401(v=vs.85).aspx</returns>
        private uint OnUnhandledExceptionFilter(IntPtr pException)
        {
            lock (m_UnhandledExceptionSyncRoot)
            {
                try
                {
                    m_UnhandledExceptionConfiguration.OnUnhandledNativeExceptionFilter(pException);
                    return 1;
                }
                catch (Exception ex)
                {
                    bool isNeedToReThrown = OnUnhandledManagedException(ex);
                    if (isNeedToReThrown)
                    {
                        throw;
                    }

                    return 1;
                }
            }
        }
    }
}