using System;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Attribute for the structure's fields,
    /// which informs about the native name of that field.
    /// This attribute only for information purposes, and the main target it aims -
    /// helping in the process of the appropriate field while working with the native API
    /// </summary>
    [AttributeUsage(AttributeTargets.Field)]
    internal class NativeNameAttribute : Attribute
    {
        /// <summary>
        /// Gets or sets the native name for the field
        /// </summary>
        public string NativeName { get; private set; }
        
        public NativeNameAttribute(string nativeName)
        {
            NativeName = nativeName;
        }
    }
}