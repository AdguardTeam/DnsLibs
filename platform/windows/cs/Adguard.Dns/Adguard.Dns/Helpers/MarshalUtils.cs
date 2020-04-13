using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Adguard.Dns.Logging;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Helper class for Marshaling objects to pointers and visa versa
    /// </summary>
    internal class MarshalUtils
    {
        private static readonly ILog LOG = LogProvider.For<MarshalUtils>();

        /// <summary>
        /// Marshals structure to the pointer include memory allocating
        /// Also .Net would try to destroy.
        /// Must be freed using <see cref="SafeFreeHGlobal(IntPtr)"/>>
        /// </summary>
        /// <param name="structure">Structure</param>
        /// <param name="allocatedPointers">
        /// Pointers, which will be referred to a newly allocated memory
        /// (within the process of marshaling the string to the pointer)
        /// will be added to this list.
        /// If this list is not specified (null),
        /// a new created pointer will not be added anywhere</param>
        /// The resulting pointer (<seealso cref="IntPtr"/>) must be freed
        /// with <see cref="SafeFreeHGlobal(IntPtr)"/>
        /// <typeparam name="T">Structure type</typeparam>
        /// <returns>Pointer to the structure</returns>
        internal static IntPtr StructureToPtr<T>(T structure, Queue<IntPtr> allocatedPointers = null) where T : struct
        {
            IntPtr pStructure = Marshal.AllocHGlobal(Marshal.SizeOf(structure));
            Marshal.StructureToPtr(structure, pStructure, false);
            if (allocatedPointers != null)
            {
                allocatedPointers.Enqueue(pStructure);
            }
            
            return pStructure;
        }

        /// <summary>
        /// Marshals list of structures to the pointer include memory allocating
        /// </summary>
        /// <param name="structures">Structure</param>
        /// <param name="allocatedPointers">
        /// Pointers, which will be referred to a newly allocated memory
        /// (within the process of marshaling the string to the pointer)
        /// will be added to this list.
        /// If this list is not specified (null),
        /// a new created pointer will not be added anywhere</param>
        /// The resulting pointer (<seealso cref="IntPtr"/>) must be freed
        /// with <see cref="SafeFreeHGlobal(IntPtr)"/>
        /// <typeparam name="T">Structure type</typeparam>
        /// <returns>Pointer to the list of structures</returns>
        private static IntPtr StructureListToPtr<T>(List<T> structures, Queue<IntPtr> allocatedPointers = null)
            where T : struct
        {
            if (!structures.Any())
            {
                return IntPtr.Zero;
            }

            int structureSize = Marshal.SizeOf(structures[0]);
            IntPtr pStructures = Marshal.AllocHGlobal(structureSize * structures.Count);
            long longPStructures = pStructures.ToInt64();
            foreach (T structure in structures)
            {
                IntPtr pStructure = new IntPtr(longPStructures);
                Marshal.StructureToPtr(structure, pStructure, false);
                longPStructures += structureSize;
            }

            if (allocatedPointers != null)
            {
                allocatedPointers.Enqueue(pStructures);
            }

            return pStructures;
        }

        /// <summary>
        /// Marshals pointer to the structure with specified type
        /// </summary>
        /// <param name="ptr">Pointer</param>
        /// <typeparam name="T">Structure's type</typeparam>
        /// <returns>Structure</returns>
        internal static T PtrToStructure<T>(IntPtr ptr) where T : struct
        {
            T structure = new T();
            if (ptr == IntPtr.Zero)
            {
                return structure;
            }

            object strObj = Marshal.PtrToStructure(ptr, typeof(T));
            if (strObj == null)
            {
                return structure;
            }

            structure = (T) strObj;
            return structure;
        }

        /// <summary>
        /// Marshals pointer to the list of structures with specified type
        /// </summary>
        /// <param name="ptr">Pointer</param>
        /// <param name="size">Size of list</param>
        /// <typeparam name="T">Structure's type</typeparam>
        /// <returns>List of the structures</returns>
        private static List<T> PtrToStructureList<T>(IntPtr ptr, int size) where T : struct
        {
            List<T> structureList = new List<T>();
            if (ptr == IntPtr.Zero)
            {
                return structureList;
            }

            if (size <= 0)
            {
                return structureList;
            }

            int structSize = Marshal.SizeOf(typeof(T));
            for (int i = 0; i < size; i++)
            {
                IntPtr movingPtr = IntPtr.Add(ptr, structSize * i);
                object structureObj = Marshal.PtrToStructure(movingPtr, typeof(T));
                if (structureObj == null)
                {
                    continue;
                }

                T structure = (T) structureObj;
                structureList.Add(structure);
            }

            return structureList;
        }

        /// <summary>
        /// Converts byte array to the <see cref="AGDnsApi.ag_buffer"/> structure include memory allocating.
        /// The resulting <see cref="AGDnsApi.ag_buffer.data"/> property must be freed
        /// with <see cref="SafeFreeHGlobal(IntPtr)"/>>
        /// </summary>
        /// <param name="buffer">Byte array to marshall</param>
        /// <param name="allocatedPointers">
        /// Pointers, which will be referred to a newly allocated memory
        /// (within the process of marshaling the string to the pointer)
        /// will be added to this list.
        /// If this list is not specified (null),
        /// a new created pointer will not be added anywhere</param>
        /// The resulting pointer (<seealso cref="IntPtr"/>) must be freed
        /// with <see cref="SafeFreeHGlobal(IntPtr)"/>
        /// <returns><see cref="AGDnsApi.ag_buffer"/> structure</returns>
        internal static AGDnsApi.ag_buffer BytesToAgBuffer(byte[] buffer, Queue<IntPtr> allocatedPointers = null)
        {
            if (buffer == null)
            {
                return new AGDnsApi.ag_buffer();
            }

            IntPtr pBuffer = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, pBuffer, buffer.Length);
            AGDnsApi.ag_buffer apiBuffer = new AGDnsApi.ag_buffer
            {
                data = pBuffer,
                size = (uint) buffer.Length
            };
            
            if (allocatedPointers != null)
            {
                allocatedPointers.Enqueue(pBuffer);
            }

            return apiBuffer;
        }

        /// <summary>
        /// Converts <see cref="AGDnsApi.ag_buffer"/> structure to the byte array
        /// </summary>
        /// <param name="agBuffer"><see cref="AGDnsApi.ag_buffer"/> structure</param>
        /// <returns>Byte array</returns>
        internal static byte[] AgBufferToBytes(AGDnsApi.ag_buffer agBuffer)
        {
            if (agBuffer.data == IntPtr.Zero)
            {
                return null;
            }

            if (agBuffer.size == 0)
            {
                return null;
            }

            byte[] buffer = new byte[agBuffer.size];
            Marshal.Copy(agBuffer.data, buffer, 0, (int) agBuffer.size);
            return buffer;
        }

        /// <summary>
        /// Frees memory, allocated for the specified pointer
        /// </summary>
        /// <param name="ptr">Pointer to free</param>
        internal static void SafeFreeHGlobal(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return;
            }

            Marshal.FreeHGlobal(ptr);
        }

        /// <summary>
        /// Frees memory,
        /// allocated for the pointers in the specified queue
        /// </summary>
        /// <param name="allocatedPointers">The <see cref="Queue{T}"/>
        /// of the <see cref="IntPtr"/>s to free</param>
        internal static void SafeFreeHGlobal(Queue<IntPtr> allocatedPointers)
        {
            if (allocatedPointers == null)
            {
                return;
            }

            while (allocatedPointers.Count > 0)
            {
                IntPtr ptr = allocatedPointers.Dequeue();
                SafeFreeHGlobal(ptr);
            }
        }

        /// <summary>
        /// Reads specified <see cref="pInt"/> to the <see cref="UInt32"/> and
        /// returns resulting value
        /// </summary>
        /// <param name="pInt">Pointer to the int
        /// (<seealso cref="IntPtr"/></param>
        /// <returns>Resulting integer or null in case of <see cref="IntPtr.Zero"/>
        /// (<seealso cref="UInt32"/>)</returns>
        internal static int? PtrToNullableInt(IntPtr pInt)
        {
            if (pInt == IntPtr.Zero)
            {
                return null;
            }

            return Marshal.ReadInt32(pInt);
        }

        /// <summary>
        /// Writes specified string to the pointer and returns it
        /// </summary>
        /// <param name="str">String to write</param>
        /// <param name="allocatedPointers">List of pointers, which were allocated.
        /// Pointers, which will be referred to a newly allocated memory
        /// (within the process of marshaling the string to the pointer)
        /// will be added to this list.
        /// If this list is not specified (null),
        /// a new created pointer will not be added anywhere</param>
        /// The resulting pointer (<seealso cref="IntPtr"/>) must be freed
        /// with <see cref="SafeFreeHGlobal(IntPtr)"/>
        /// <returns>Pointer to the string</returns>
        internal static IntPtr StringToPtr(string str, Queue<IntPtr> allocatedPointers = null)
        {
            if (str == null)
            {
                return IntPtr.Zero;
            }

            int fullStringLengthInMemory = Encoding.UTF8.GetBytes(str).Length + 1;
            IntPtr pStr = Marshal.AllocHGlobal(fullStringLengthInMemory);
            if (!StringToPtr(pStr, str, fullStringLengthInMemory))
            {
                SafeFreeHGlobal(pStr);
                return IntPtr.Zero;
            }

            if (allocatedPointers != null)
            {
                allocatedPointers.Enqueue(pStr);
            }

            return pStr;
        }

        /// <summary>
        /// Writes specified string to the specified pointer
        /// </summary>
        /// <param name="pStr">Pointer, where string must be written</param>
        /// <param name="str">String to write</param>
        /// <param name="maxLength">Maximum string's UTF8 byte representation length.
        /// If not specified <see cref="System.Int32.MaxValue"/> is used</param>
        /// <exception cref="ArgumentException">Thrown, if specified string's UTF8 byte
        /// representation longer than <see cref="maxLength"/></exception>
        /// <returns>True, if marshaling completed successfully, otherwise false</returns>
        private static bool StringToPtr(IntPtr pStr, string str, int maxLength = Int32.MaxValue)
        {
            if (str == null)
            {
                return false;
            }

            byte[] buffer = Encoding.UTF8.GetBytes(str);
            if (buffer.Length + 1 > maxLength)
            {
                string message = string.Format(
                    "String's UTF8 byte representation {0}(byte array length is {1}) longer than maximum value {2} ",
                    str,
                    buffer.Length,
                    maxLength);
                throw new ArgumentException(message, "str");
            }

            Marshal.Copy(buffer, 0, pStr, buffer.Length);
            Marshal.WriteByte(pStr, buffer.Length, 0);
            return true;
        }

        /// <summary>
        /// Reads specified <see cref="pStr"/> to the null-terminated <see cref="string"/> and
        /// returns resulting string
        /// </summary>
        /// <param name="pStr">Pointer to the string
        /// (<seealso cref="IntPtr"/></param>
        /// <returns>Resulting string
        /// (<seealso cref="string"/>)</returns>
        internal static string PtrToString(IntPtr pStr)
        {
            if (pStr == IntPtr.Zero)
            {
                return null;
            }

            int offset = 0;
            List<byte> bufferList = new List<byte>();
            byte read;
            do
            {
                read = Marshal.ReadByte(pStr, offset);
                if (read == 0)
                {
                    continue;
                }

                offset++;
                bufferList.Add(read);
            } while (read != 0);

            byte[] buffer = bufferList.ToArray();
            string str = Encoding.UTF8.GetString(buffer);
            return str;
        }

        #region Marshal Ptr to string and visa versa in structures

        private static readonly BindingFlags FIELD_BINDING_FLAGS = BindingFlags.Instance |
                                                                   BindingFlags.NonPublic |
                                                                   BindingFlags.Public |
                                                                   BindingFlags.SetField |
                                                                   BindingFlags.GetField;

        private static readonly BindingFlags PROPERTY_BINDING_FLAGS = BindingFlags.Instance |
                                                                      BindingFlags.NonPublic |
                                                                      BindingFlags.Public |
                                                                      BindingFlags.GetProperty |
                                                                      BindingFlags.SetProperty;

        /// <summary>
        /// Manual marshals all the pointers (<seealso cref="IntPtr"/>),
        /// marked with the attribute <see cref="ManualMarshalPtrToStringAttribute"/>
        /// from the <see cref="sourceStructure"/>
        /// (which has the type <typeparam name="TStruct"></typeparam>)
        /// to the string properties (<seealso cref="string"/>) with the same names
        /// in the <see cref="destinationClass"/>
        /// (which has the type <typeparam name="TClass"></typeparam>)
        ///
        /// It's very important to use the raw pointer and marshal
        /// it further manually instead of using dotNet's built-in marshaller
        /// (<see cref="MarshalAsAttribute"/> with <see cref="UnmanagedType.LPStr"/> parameter means),
        /// because the original string may contain non-utf8 characters,
        /// which in turn can lead to crash within the process
        /// of marshaling (via <see cref="Marshal.PtrToStructure(IntPtr, Type)"/> method)
        /// </summary>
        /// <param name="sourceStructure">Source structure
        /// with type <typeparam name="TStruct"></typeparam></param>
        /// <param name="destinationClass">Destination class
        /// with type <typeparam name="TClass"></typeparam></param>
        /// <typeparam name="TStruct">Type of <see cref="sourceStructure"/></typeparam>
        /// <typeparam name="TClass">Type of <see cref="destinationClass"/></typeparam>
        /// <exception cref="ArgumentNullException">Thrown,
        /// if the <see cref="destinationClass"/> is null</exception>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if the <see cref="sourceStructure"/> has
        /// any fields with attribute <see cref="ManualMarshalPtrToStringAttribute"/>,
        /// but type different from
        /// <see cref="IntPtr"/></exception>
        internal static void AllPtrsToStrings<TStruct, TClass>(
            TStruct sourceStructure,
            TClass destinationClass)
            where TStruct : struct
        {
            if (destinationClass == null)
            {
                throw new ArgumentNullException("destinationClass");
            }

            FieldInfo[] sourceFieldInfos = typeof(TStruct).GetFields(FIELD_BINDING_FLAGS);
            foreach (FieldInfo sourceFieldInfo in sourceFieldInfos)
            {
                if (!Attribute.IsDefined(sourceFieldInfo, typeof(ManualMarshalPtrToStringAttribute)))
                {
                    continue;
                }

                if (sourceFieldInfo.FieldType != typeof(IntPtr))
                {
                    string errorMessage = string.Format(
                        "Attribute {0} cannot be applied to field \"{1}\" with type \"{2}\"",
                        typeof(ManualMarshalPtrToStringAttribute).Name,
                        sourceFieldInfo.Name,
                        sourceFieldInfo.FieldType.Name);
                    throw new InvalidOperationException(errorMessage);
                }

                object pSourceStringValueObject = sourceFieldInfo.GetValue(sourceStructure);
                if (pSourceStringValueObject == null)
                {
                    continue;
                }

                PropertyInfo destinationPropertyInfo = typeof(TClass).GetProperty(
                    sourceFieldInfo.Name,
                    PROPERTY_BINDING_FLAGS);

                if (destinationPropertyInfo == null ||
                    destinationPropertyInfo.PropertyType != typeof(string))
                {
                    LOG.WarnFormat("Class {0} doesn't contain property {1} with the type {2}",
                        typeof(TClass).Name,
                        sourceFieldInfo.Name,
                        typeof(string).Name);
                    continue;
                }

                IntPtr pStringValue = (IntPtr) pSourceStringValueObject;
                string stringValue = PtrToString(pStringValue);
                destinationPropertyInfo.SetValue(destinationClass, stringValue, null);
            }
        }
        
        /// <summary>
        /// Copies all the fields of the <see cref="sourceStructure"/> to the properties of
        /// <see cref="destinationClass"/> with the same names and types.
        /// </summary>
        /// <param name="sourceStructure">Source structure
        /// with type <typeparam name="TStruct"></typeparam></param>
        /// <param name="destinationClass">Destination class
        /// with type <typeparam name="TClass"></typeparam></param>
        /// <typeparam name="TStruct">Type of <see cref="sourceStructure"/></typeparam>
        /// <typeparam name="TClass">Type of <see cref="destinationClass"/></typeparam>
        /// <exception cref="ArgumentNullException">Thrown,
        /// if the <see cref="destinationClass"/> is null</exception>
        internal static void CopyFieldsToProperties<TStruct, TClass>(
            TStruct sourceStructure,
            TClass destinationClass)
            where TStruct : struct
        {
            if (destinationClass == null)
            {
                throw new ArgumentNullException("destinationClass");
            }

            FieldInfo[] sourceFieldInfos = typeof(TStruct).GetFields(FIELD_BINDING_FLAGS);
            foreach (FieldInfo sourceFieldInfo in sourceFieldInfos)
            {
                object sourceValueObject = sourceFieldInfo.GetValue(sourceStructure);
                if (sourceValueObject == null)
                {
                    continue;
                }

                PropertyInfo destinationPropertyInfo = typeof(TClass).GetProperty(
                    sourceFieldInfo.Name,
                    PROPERTY_BINDING_FLAGS);

                if (destinationPropertyInfo == null ||
                    destinationPropertyInfo.PropertyType != sourceFieldInfo.FieldType)
                {
                    LOG.WarnFormat("Class {0} doesn't contain property {1} with the type {2}",
                        typeof(TClass).Name,
                        sourceFieldInfo.Name,
                        sourceFieldInfo.FieldType.Name);
                    continue;
                }

                destinationPropertyInfo.SetValue(destinationClass, sourceValueObject, null);
            }
        }

        /// <summary>
        /// Manual marshals all the strings (<seealso cref="string"/>),
        /// marked with the attribute <see cref="ManualMarshalStringToPtrAttribute"/>
        /// from the <see cref="sourceClass"/>
        /// (which has the type <typeparam name="TClass"></typeparam>)
        /// to the pointers properties (<seealso cref="IntPtr"/>) with the same names
        /// in the <see cref="destinationStructure"/>
        /// (which has the type <typeparam name="TClass"></typeparam>) include memory allocating.
        /// All the created pointers are stored in the <see cref="allocatedPointers"/> queue,
        /// in order to free them further with <see cref="SafeFreeHGlobal(Queue{IntPtr})"/>
        ///
        /// It's very important to use the raw pointer and marshal
        /// it further manually instead of using dotNet's built-in marshaller
        /// (<see cref="MarshalAsAttribute"/> with <see cref="UnmanagedType.LPStr"/> parameter means),
        /// because the original string may contain non-utf8 characters,
        /// which in turn can lead to crash within the process
        /// of marshaling (via <see cref="Marshal.StructureToPtr"/> method)
        /// </summary>
        /// <param name="sourceClass">Source class
        /// with type <typeparam name="TClass"></typeparam></param>
        /// <param name="destinationStructure"> Structure
        /// with type <typeparam name="TStruct"> </typeparam></param>
        /// <param name="allocatedPointers">Queue of pointers,
        /// which contains pointer for further freeing with <see cref="SafeFreeHGlobal(Queue{IntPtr})"/>
        /// All the pointers, which will be refer to a new allocated memory
        /// (within the process of marshalling the string to the pointers),
        /// will be added to this queue</param>
        /// <typeparam name="TClass">Type of <see cref="sourceClass"/></typeparam>
        /// <typeparam name="TStruct">Type of <see cref="destinationStructure"/></typeparam>
        /// <exception cref="ArgumentNullException">Thrown, if the <see cref="sourceClass"/>
        /// and/or <see cref="allocatedPointers"/> are null</exception>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if the <see cref="sourceClass"/> has
        /// any fields with attribute <see cref="ManualMarshalStringToPtrAttribute"/>,
        /// but type different from
        /// <see cref="string"/></exception>
        internal static void AllStringsToPtrs<TClass, TStruct>(
            TClass sourceClass,
            ref TStruct destinationStructure,
            Queue<IntPtr> allocatedPointers)
            where TClass : class
            where TStruct : struct
        {
            if (sourceClass == null)
            {
                throw new ArgumentNullException("sourceClass");
            }

            if (allocatedPointers == null)
            {
                throw new ArgumentNullException("allocatedPointers");
            }

            object destinationStructureObj = destinationStructure;
            PropertyInfo[] sourcePropertyInfos = typeof(TClass).GetProperties(PROPERTY_BINDING_FLAGS);
            foreach (PropertyInfo sourcePropertyInfo in sourcePropertyInfos)
            {
                if (!Attribute.IsDefined(sourcePropertyInfo, typeof(ManualMarshalStringToPtrAttribute)))
                {
                    continue;
                }

                if (sourcePropertyInfo.PropertyType != typeof(string))
                {
                    string errorMessage = string.Format(
                        "Attribute {0} cannot be applied to field \"{1}\" with type \"{2}\"",
                        typeof(ManualMarshalStringToPtrAttribute).Name,
                        sourcePropertyInfo.Name,
                        sourcePropertyInfo.PropertyType.Name);
                    throw new InvalidOperationException(errorMessage);
                }

                object sourceStringValueObject = sourcePropertyInfo.GetValue(sourceClass);
                if (sourceStringValueObject == null)
                {
                    continue;
                }

                FieldInfo destinationStructureFieldInfo = typeof(TStruct).GetField(
                    sourcePropertyInfo.Name,
                    FIELD_BINDING_FLAGS);

                if (destinationStructureFieldInfo == null ||
                    destinationStructureFieldInfo.FieldType != typeof(IntPtr))
                {
                    LOG.WarnFormat("Structure {0} doesn't contain field {1} with the type {2}",
                        typeof(TStruct).Name,
                        sourcePropertyInfo.Name,
                        typeof(IntPtr).Name);
                    continue;
                }

                string stringValue = (string) sourceStringValueObject;
                IntPtr pStringValue = StringToPtr(stringValue, allocatedPointers);
                destinationStructureFieldInfo.SetValue(destinationStructureObj, pStringValue);
                destinationStructure = (TStruct) destinationStructureObj;
            }
        }
        
        /// <summary>
        /// Copies all the properties values from the <see cref="sourceClass"/> into
        /// the fields from the <see cref="destinationStructure"/> with the same names and types.
        /// </summary>
        /// <param name="sourceClass">Source class
        /// with type <typeparam name="TClass"></typeparam></param>
        /// <param name="destinationStructure"> Structure
        /// with type <typeparam name="TStruct"> </typeparam></param>
        /// <typeparam name="TClass">Type of <see cref="sourceClass"/></typeparam>
        /// <typeparam name="TStruct">Type of <see cref="destinationStructure"/></typeparam>
        /// <exception cref="ArgumentNullException">Thrown,
        /// if the <see cref="sourceClass"/> is null</exception>
        internal static void CopyPropertiesToFields<TClass, TStruct>(
            TClass sourceClass,
            ref TStruct destinationStructure)
            where TClass : class
            where TStruct : struct
        {
            if (sourceClass == null)
            {
                throw new ArgumentNullException("sourceClass");
            }

            object destinationObj = destinationStructure;
            PropertyInfo[] propertyInfos = typeof(TClass).GetProperties(PROPERTY_BINDING_FLAGS);
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {

                object sourceValueObject = propertyInfo.GetValue(sourceClass);
                if (sourceValueObject == null)
                {
                    continue;
                }

                FieldInfo destinationFieldInfo = typeof(TStruct).GetField(
                    propertyInfo.Name,
                    FIELD_BINDING_FLAGS);

                if (destinationFieldInfo == null ||
                    destinationFieldInfo.FieldType != propertyInfo.PropertyType)
                {
                    LOG.WarnFormat("Structure {0} doesn't contain field {1} with the type {2}",
                        typeof(TStruct).Name,
                        propertyInfo.Name,
                        propertyInfo.PropertyType.Name);
                    continue;
                }

                destinationFieldInfo.SetValue(destinationObj, sourceValueObject);
                destinationStructure = (TStruct) destinationObj;
            }
        }
        
        /// <summary>
        /// Converts the specified <see cref="sourceList"/> with elements
        /// with the type <see cref="TSourceClassElement"/> to the <see cref="AGDnsApi.ag_list"/> instance.
        /// Result <see cref="AGDnsApi.ag_list"/> instance points to the array of structures
        /// with the type <see cref="TDestinationStructElement"/>.
        /// All the created pointers are stored in the <see cref="allocatedPointers"/> queue,
        /// in order to free them further with <see cref="SafeFreeHGlobal(Queue{IntPtr})"/>
        /// </summary>
        /// <param name="sourceList">Source list of elements with type <see cref="TSourceClassElement"/></param>
        /// <param name="converterFunc">Function to convert element with type <see cref="TSourceClassElement"/>
        /// to the struct with the type <see cref="TDestinationStructElement"/></param>
        /// <param name="allocatedPointers">Queue of pointers,
        /// which contains pointer for further freeing with <see cref="SafeFreeHGlobal(Queue{IntPtr})"/>
        /// All the pointers, which will be refer to a new allocated memory
        /// (within the process of marshalling the string to the pointers),
        /// will be added to this queue</param>
        /// <typeparam name="TSourceClassElement">Type of the elements from <see cref="sourceList"/>,
        /// which will be converted</typeparam>
        /// <typeparam name="TDestinationStructElement">Type of the result structure,
        /// where the element with the type <see cref="TSourceClassElement"/> will be converted to</typeparam>
        /// <exception cref="ArgumentNullException">Thrown, if the <see cref="sourceList"/>
        /// and/or <see cref="allocatedPointers"/> are null</exception>
        /// <returns>An <see cref="AGDnsApi.ag_list"/> instance</returns>
        internal static AGDnsApi.ag_list ListToAgList<TSourceClassElement, TDestinationStructElement>(
            List<TSourceClassElement> sourceList,
            Func<TSourceClassElement, Queue<IntPtr>, TDestinationStructElement> converterFunc,
            Queue<IntPtr> allocatedPointers) where TDestinationStructElement : struct
        {
            if (sourceList == null)
            {
                throw new ArgumentNullException("sourceList");
            }

            if (allocatedPointers == null)
            {
                throw new ArgumentNullException("allocatedPointers");
            }
            
            List<TDestinationStructElement> listC = new List<TDestinationStructElement>();
            foreach (TSourceClassElement element in sourceList)
            {
                TDestinationStructElement elementC = converterFunc(element, allocatedPointers);
                listC.Add(elementC);
            }

            IntPtr pListC = StructureListToPtr(listC, allocatedPointers);
            AGDnsApi.ag_list agListC = new AGDnsApi.ag_list
            {
                entries = pListC,
                num_entries = (uint) sourceList.Count
            };

            return agListC;
        } 
        
        /// <summary>
        /// Converts the specified <see cref="sourceAgList"/> with the type <see cref="AGDnsApi.ag_list"/>
        /// and which points to the array of structures with the type <see cref="TSourceStructElement"/>.
        /// to the <see cref="List{T}"/> with elements with the type <see cref="TDestinationClassElement"/>
        /// </summary>
        /// <param name="sourceAgList">An <see cref="AGDnsApi.ag_list"/> instance</param>
        /// <param name="converterFunc">Function to convert element with type <see cref="TSourceStructElement"/>
        /// to the struct with the type <see cref="TDestinationClassElement"/></param>
        /// <typeparam name="TSourceStructElement">Type of the result structure,
        /// which will be converted</typeparam>
        /// <typeparam name="TDestinationClassElement">Type of the result element,
        /// where the element with the type <see cref="TSourceStructElement"/> will be converted to</typeparam>
        /// <returns>An <see cref="AGDnsApi.ag_list"/> instance</returns>
        internal static List<TDestinationClassElement> AgListToList<TSourceStructElement, TDestinationClassElement>(
            AGDnsApi.ag_list sourceAgList,
            Func<TSourceStructElement, TDestinationClassElement> converterFunc) where TSourceStructElement : struct
        {
            List<TSourceStructElement> listC = 
                PtrToStructureList<TSourceStructElement>(sourceAgList.entries, (int) sourceAgList.num_entries);
            
            List<TDestinationClassElement> list = new List<TDestinationClassElement>();
            foreach (TSourceStructElement elementC in listC)
            {
                TDestinationClassElement element = converterFunc(elementC);
                list.Add(element);
            }

            return list;
        }

        #endregion

        
    }
}