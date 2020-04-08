using System;
using System.Runtime.InteropServices;
using Adguard.Dns.Logging;

namespace Adguard.Dns.Helpers
{
    // ReSharper disable InconsistentNaming
    /// <summary>
    /// Helper class for dynamically invoking methods from native dlls
    /// </summary>
    internal class DynamicDllFunctions : IDisposable
    {
        private static readonly ILog LOG = LogProvider.For<DynamicDllFunctions>();

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        /// <summary>
        /// Gets or sets the library pointer
        /// (<seealso cref="IntPtr"/>)
        /// </summary>
        private readonly IntPtr m_pDll;

        /// <summary>
        /// Creates an instance of <see cref="DynamicDllFunctions"/> object
        /// </summary>
        /// <param name="dllName">Dll name</param>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot load specified dll </exception>
        internal DynamicDllFunctions(string dllName)
        {
            m_pDll = LoadLibrary(dllName);
            if (m_pDll != IntPtr.Zero)
            {
                LOG.InfoFormat("Library \"{0}\" has been loaded successfully", dllName);
                return;
            }

            int errorCode = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                string.Format("Failed to load library \"{0}\" (ErrorCode: {1})",
                    dllName,
                    errorCode));
        }

        /// <summary>
        /// Gets the specified delegate with type <typeparam name="T"></typeparam>
        /// and name <see cref="functionName"/> from the previously loaded dll (<seealso cref="m_pDll"/>)
        /// </summary>
        /// <param name="functionName">Function name</param>
        /// <typeparam name="T">Type of the delegate</typeparam>
        /// <returns>Delegate for the specified function</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot load specified function from the previously loaded dll</exception>
        internal T GetDelegate<T>(string functionName) where T: class
        {
            IntPtr pFunction = GetProcAddress(m_pDll, functionName);
            if (pFunction == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new InvalidOperationException(
                    string.Format("Failed to load function \"{0}\" (ErrorCode: {1})",
                        functionName,
                        errorCode));
            }

            Delegate function = Marshal.GetDelegateForFunctionPointer(pFunction, typeof(T));
            LOG.InfoFormat("Function \"{0}\" ({1}) has been loaded successfully",
                functionName,
                function.Method.Name);
            return function as T;
        }

        public void Dispose()
        {
            if (m_pDll == IntPtr.Zero)
            {
                return;
            }

            FreeLibrary(m_pDll);
        }
    }
}