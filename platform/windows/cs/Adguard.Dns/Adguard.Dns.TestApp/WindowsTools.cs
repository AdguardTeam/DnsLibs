using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Adguard.Dns.TestApp
{
    /// <summary>
    /// Tools for working with Windows
    /// </summary>
    internal static class WindowsTools
    {
        private const int X64_BIT_ENABLED = 1;
        private const int X64_BIT_DISABLED = 0;

        #region Win32 constants and helpers

        // ReSharper disable InconsistentNaming
        // ReSharper disable RedundantAssignment
        // ReSharper disable UnusedMember.Local

        const int ERROR_NO_MORE_ITEMS = 259;

        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenElevation = 20
        }

        private const int SM_TABLETPC = 86;
        private const uint TOKEN_QUERY = 0x0008;

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle,
                                                    UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private  static extern int GetComPlusPackageInstallStatus();

        [DllImport("kernel32.dll")]
        private static extern int SetComPlusPackageInstallStatus(int status);

        #endregion

        #region Windows versions and platforms

        /// <summary>
        /// Determines whether current OS is Windows Vista and later
        /// </summary>
        private static bool IsVistaOrNewer
        {
            get
            {
                return Environment.OSVersion.Version.Major >= 6;
            }
        }

        #endregion

        #region Application access rights

        /// <summary>
        /// Checks if user is admin or not
        /// </summary>
        /// <returns>True if the current process is started under Admin privileges, otherwise false</returns>
        private static bool IsAdmin
        {
            get
            {
                bool isAdmin;
                try
                {
                    var user = WindowsIdentity.GetCurrent();
                    var principal = new WindowsPrincipal(user);
                    isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch (UnauthorizedAccessException)
                {
                    isAdmin = false;
                }
                catch (Exception)
                {
                    isAdmin = false;
                }

                return isAdmin;
            }
        }

        /// <summary>
        /// Checks if process is really elevated
        /// </summary>
        /// <returns>True if the current process is elevated, otherwise false</returns>
        private static bool IsProcessElevated
        {
            get
            {
                try
                {
                    var hToken = IntPtr.Zero;
                    var hProcess = GetCurrentProcess();

                    if (hProcess == IntPtr.Zero)
                    {
                        throw new WindowsToolsException("Error getting current process handle");
                    }

                    var bRetVal = OpenProcessToken(hProcess, TOKEN_QUERY, out hToken);


                    if (!bRetVal)
                    {
                        throw new WindowsToolsException("Error opening process token");
                    }
                    try
                    {
                        TOKEN_ELEVATION te;
                        te.TokenIsElevated = 0;

                        var teSize = Marshal.SizeOf(te);
                        var pTe = Marshal.AllocHGlobal(teSize);
                        try
                        {
                            Marshal.StructureToPtr(te, pTe, true);

                            UInt32 dwReturnLength = 0;
                            bRetVal = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, pTe, (UInt32)teSize,
                                                          out dwReturnLength);

                            if (!bRetVal | (teSize != dwReturnLength))
                            {
                                throw new WindowsToolsException("Error getting token information");
                            }

                            te = (TOKEN_ELEVATION)Marshal.PtrToStructure(pTe, typeof(TOKEN_ELEVATION));
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(pTe);
                        }

                        return te.TokenIsElevated != 0;
                    }
                    finally
                    {
                        CloseHandle(hToken);
                    }
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        /// <summary>
        ///     The possible values are:
        ///     TRUE - the current process is elevated.
        ///     This value indicates that either UAC is enabled, and the process was elevated by
        ///     the administrator, or that UAC is disabled and the process was started by a user
        ///     who is a member of the Administrators group.
        ///     FALSE - the current process is not elevated (limited).
        ///     This value indicates that either UAC is enabled, and the process was started normally,
        ///     without the elevation, or that UAC is disabled and the process was started by a standard user.
        /// </summary>
        /// <returns>True if the current process is elevated, otherwise false</returns>
        private static bool IsElevated //= NULL )
        {
            get
            {
                return IsAdmin || IsProcessElevated;
            }
        }

        #endregion

        #region Helpers for executing cmd command

        /// <summary>
        /// Appends <see cref="data"/> to the <see cref="output"/>
        /// (<seealso cref="StringBuilder"/>) as a new line
        /// </summary>
        /// <param name="data">Data to append</param>
        /// <param name="output">Output text "stream"
        /// (<seealso cref="StringBuilder"/>)</param>
        private static void AppendDataToOutput(string data, StringBuilder output)
        {
            if (data.EndsWith(Environment.NewLine) ||
                data.EndsWith("\n"))
            {
                output.Append(data);
            }

            output.AppendLine(data);
        }

        /// <summary>
        /// Creates process with specified arguments
        /// </summary>
        /// <param name="fileName">Executable file name</param>
        /// <param name="arguments">Command arguments</param>
        /// <param name="elevate">If "true" - checks if process is elevated. If not - elevates it.</param>
        /// <returns>Process ready to be started</returns>
        internal static Process CreateProcess(string fileName, string arguments, bool elevate)
        {
            Process process = new Process
            {
                StartInfo =
                {
                    FileName = fileName,
                    Arguments = arguments,
                    CreateNoWindow = true
                }
            };

            if (elevate && IsVistaOrNewer && !IsElevated)
            {
                // Elevating process
                process.StartInfo.Verb = "runas";
                // Using shell execute
                process.StartInfo.RedirectStandardOutput = false;
                process.StartInfo.RedirectStandardError = false;
                process.StartInfo.RedirectStandardInput = false;
                process.StartInfo.UseShellExecute = false;
            }
            else
            {
                // Process is not elevated, redirecting standard output
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.RedirectStandardInput = true;
                process.StartInfo.UseShellExecute = false;
            }

            return process;
        }

        /// <summary>
        /// Uses a workaround russian localized windows.
        /// It converts cp866 to cp1251.
        /// </summary>
        /// <param name="output">Output</param>
        /// <returns>Converted output</returns>
        private static string ConvertConsoleOutput(string output)
        {
            if (IsVistaOrNewer || !Equals(Encoding.Default, Encoding.GetEncoding(1251)))
            {
                return output;
            }

            // Workaround for russian localized windows
            var cp866 = Encoding.GetEncoding(866);
            var cp1251 = Encoding.Default;

            var b = cp1251.GetBytes(output);
            var d = Encoding.Convert(cp866, cp1251, b);
            var c = new char[cp1251.GetCharCount(d, 0, d.Length)];
            cp1251.GetChars(d, 0, d.Length, c, 0);

            output = new string(c);

            return output;
        }

        /// <summary>
        /// Enables "Enable64Bit" flag in the registry if needed
        /// If this flag is enabled on the x64 bit OS all .Net framework applications compiled as AnyCPU
        /// will run as x64 bit processes, otherwise as x86
        /// </summary>
        /// <returns>True - if flag was enabled, otherwise false</returns>
        private static bool Enable64Bit()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }

            try
            {
                var currentState = GetComPlusPackageInstallStatus();
                if (currentState != X64_BIT_DISABLED)
                {
                    return false;
                }

                SetComPlusPackageInstallStatus(X64_BIT_ENABLED);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Disables "Enable64Bit" flag in the registry
        /// If this flag is enabled on the x64 bit OS all .Net framework applications compiled as AnyCPU
        /// will run as x64 bit processes, otherwise as x86
        /// </summary>
        private static void Disable64Bit()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return;
            }

            try
            {
                SetComPlusPackageInstallStatus(X64_BIT_DISABLED);
            }
            catch (Exception)
            {
                // ignored
            }
        }


        #endregion
    }

    #region TOKEN types (for win32 methods)

    internal struct TOKEN_ELEVATION
    {
        internal UInt32 TokenIsElevated;
    }

    #endregion

    #region Exception for windows tools

    internal class WindowsToolsException : ApplicationException
    {
        // Constructor accepting a single string message
        internal WindowsToolsException(string message)
            : base(message)
        {
        }
    }

    #endregion
}