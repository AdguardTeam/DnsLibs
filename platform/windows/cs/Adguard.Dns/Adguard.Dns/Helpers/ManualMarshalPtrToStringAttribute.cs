using System;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Attribute for the structure's fields (with type <see cref="IntPtr"/>),
    /// which informs, that this field should be marshaled to the <see cref="string"/> manually
    /// (<seealso cref="MarshalUtils.AllPtrsToStrings{TClass, TStruct}"/>)
    /// </summary>
    [AttributeUsage(AttributeTargets.Field)]
    internal class ManualMarshalPtrToStringAttribute : Attribute
    {

    }
}