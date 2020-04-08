using System;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Attribute for the class' property (with type <see cref="string"/>),
    /// which informs, that this property should be marshaled to the <see cref="IntPtr"/> manually
    /// (<seealso cref="MarshalUtils.AllStringsToPtrs{TClass, TStruct}"/>)
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    internal class ManualMarshalStringToPtrAttribute : Attribute
    {

    }
}