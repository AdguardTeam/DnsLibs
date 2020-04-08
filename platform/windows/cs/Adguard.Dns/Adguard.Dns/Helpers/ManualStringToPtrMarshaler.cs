using System;
using System.Runtime.InteropServices;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Marshaller for manual marshaling <see cref="string"/> to <see cref="IntPtr"/>
    /// </summary>
    internal class ManualStringToPtrMarshaler : ICustomMarshaler
    {
        /// <summary>
        /// Converts the unmanaged data to managed data.
        /// </summary>
        /// <param name="pNativeData">A pointer to the unmanaged data to be wrapped. </param>
        /// <returns>An object that represents the managed view of the COM data.</returns>
        public object MarshalNativeToManaged(IntPtr pNativeData)
        {
            string managedString = MarshalUtils.PtrToString(pNativeData);
            return managedString;
        }

        /// <summary>
        /// Converts the managed data to unmanaged data.
        /// </summary>
        /// <param name="managedObj">The managed object to be converted. </param>
        /// <returns>A pointer to the COM view of the managed object.</returns>
        public IntPtr MarshalManagedToNative(object managedObj)
        {
            string managedString = managedObj as string;
            IntPtr pManagedString = MarshalUtils.StringToPtr(managedString);
            return pManagedString;
        }

        /// <summary>
        /// Performs necessary cleanup of the unmanaged data when it is no longer needed.
        /// </summary>
        /// <param name="pNativeData">A pointer to the unmanaged data to be destroyed. </param>
        public void CleanUpNativeData(IntPtr pNativeData)
        {
            MarshalUtils.SafeFreeHGlobal(pNativeData);
        }

        /// <summary>
        /// Performs necessary cleanup of the managed data when it is no longer needed.
        /// </summary>
        /// <param name="managedObj">The managed object to be destroyed. </param>
        public void CleanUpManagedData(object managedObj)
        {

        }

        /// <summary>
        /// Returns the size of the native data to be marshaled.
        /// </summary>
        /// <returns> The size, in bytes, of the native data.</returns>
        public int GetNativeDataSize()
        {
            return IntPtr.Size;
        }

        private static readonly ManualStringToPtrMarshaler INSTANCE = new ManualStringToPtrMarshaler();

        /// <summary>
        /// Gets a instance of the <see cref="ICustomMarshaler"/> implementation
        /// This static method is called by the common language runtime's COM interop layer
        /// to instantiate an instance of the custom marshaler.
        /// The string that is passed to GetInstance is a cookie that the
        /// method can use to customize the returned custom marshaler.
        /// </summary>
        /// <param name="cookie">Cookie that the method can use to customize the returned custom marshaler</param>
        /// <returns>The <see cref="ICustomMarshaler"/> instance</returns>
        public static ICustomMarshaler GetInstance(string cookie)
        {
            return INSTANCE;
        }
    }
}