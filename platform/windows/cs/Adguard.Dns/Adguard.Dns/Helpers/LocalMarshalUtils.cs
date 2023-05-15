using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Local marshal utils
    /// </summary>
    public static class LocalMarshalUtils
    {
        /// <summary>
        /// Writes the specified <see cref="boolValue"/> to the pointer as Byte object
        /// </summary>
        /// <param name="boolValue">Bool value</param>
        /// <param name="allocatedPointers">Queue of pointers,
        /// which contains pointer for further freeing with <see cref="M:AdGuard.Utils.Adapters.Interop.MarshalUtils.SafeFreeHGlobal(System.Collections.Generic.Queue{System.IntPtr})" />
        /// All the pointers, which will be refer to a new allocated memory
        /// (within the process of marshalling the string to the pointers),
        /// will be added to this queue</param>
        /// <returns>Pointer to the stored boolean value</returns>
        public static IntPtr WriteBoolToPtr(bool boolValue, Queue<IntPtr> allocatedPointers = null)
        {
            IntPtr pBool = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Byte)));
            Marshal.WriteByte(pBool, Convert.ToByte(boolValue));
            allocatedPointers?.Enqueue(pBool);
            return pBool;
        }
        
        /// <summary>
        /// Reads the boolean value from the specified <see cref="pBool"/> pointer
        /// </summary>
        /// <param name="pBool">Pointer to the stored boolean value (as Byte object)</param>
        /// <returns>Stored boolean value</returns>
        public static bool ReadBoolFromPtr(IntPtr pBool)
        {
            byte boolValue = Marshal.ReadByte(pBool);
            return Convert.ToBoolean(boolValue);
        }
    }
}