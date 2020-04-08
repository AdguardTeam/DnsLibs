using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Adguard.Dns.Helpers;
using NUnit.Framework;

namespace Adguard.Dns.Tests.Helpers
{
    [TestFixture]
    public class TestMarshalUtils
    {
        [Test]
        public void TestPtrToString()
        {
            string testString = "this is test string";
            byte[] bufferWithoutTrash = Encoding.UTF8.GetBytes(testString);
            byte[] bufferWithEmoji = {65, 32, /* 🤪 */ 0xf0, 0x9f, 0xa4, 0xaa};
            byte[] bufferWithNonUtf = {65, 32, 0xff, 32, 0x7f, 32};
            byte[] bufferWithLatin1 = Encoding.GetEncoding("ISO-8859-1").GetBytes("hèllò");

            List<byte[]> buffers = new List<byte[]>
            {
                bufferWithoutTrash,
                bufferWithEmoji,
                bufferWithNonUtf,
                bufferWithLatin1
            };

            foreach (var buffer in buffers)
            {
                IntPtr pBuffer = IntPtr.Zero;
                try
                {
                    pBuffer = Marshal.AllocHGlobal(buffer.Length);
                    Marshal.Copy(buffer, 0, pBuffer, buffer.Length);
                    Assert.DoesNotThrow(() =>
                    {
                        MarshalUtils.PtrToString(pBuffer);
                    });
                }
                finally
                {
                    MarshalUtils.SafeFreeHGlobal(pBuffer);
                }
            }
        }

        [Test]
        public  void TestStringToPtr()
        {
            List<string> strings = new List<string>
            {
                string.Empty,
                null,
                "this is test string"
            };

            foreach (var str in strings)
            {
                IntPtr newPtr = IntPtr.Zero;
                try
                {
                    newPtr = MarshalUtils.StringToPtr(str);
                    string recoveredString = MarshalUtils.PtrToString(newPtr);
                    Assert.AreEqual(recoveredString, str);
                }
                finally
                {
                    MarshalUtils.SafeFreeHGlobal(newPtr);
                }
            }
        }

        [Test]
        public void TestPtrStructureConvert()
        {
            IntPtr pStructure = IntPtr.Zero;
            try
            {
                TestStructure structure = new TestStructure
                {
                    Uint64Val = 1,
                    StringVal = "hello",
                    IntPtrVal = (IntPtr) 0x123455,
                    Uint32Val = 18,
                    BoolVal = false,
                    EnumVal = TestEnum.One
                };
                pStructure = MarshalUtils.StructureToPtr(structure);
                Assert.AreNotEqual(pStructure, IntPtr.Zero);
                TestStructure convertedStructure = MarshalUtils.PtrToStructure<TestStructure>(pStructure);
                Assert.NotNull(convertedStructure);
                AssertStructureEquals(structure, convertedStructure);
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(pStructure);
            }
        }


        [Test]
        public void TestApiBufferConverting()
        {
            AGDnsApi.ag_buffer apiBuffer = new AGDnsApi.ag_buffer();
            try
            {
                string basicString = "krasivyeshpilinasolberiiskomsobore";
                byte[] basicBuffer = Encoding.UTF8.GetBytes(basicString);
                apiBuffer = MarshalUtils.BytesToAgBuffer(basicBuffer);
                Assert.AreNotEqual(apiBuffer.data, IntPtr.Zero);
                Assert.AreNotEqual(apiBuffer.size, 0);
                byte[] convertedBuffer = MarshalUtils.AgBufferToBytes(apiBuffer);
                Assert.AreNotEqual(convertedBuffer.Length, 0);
                string convertedString = Encoding.UTF8.GetString(convertedBuffer);
                Assert.AreEqual(basicString, convertedString);
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(apiBuffer.data);
            }
        }

        private void AssertStructureEquals(TestStructure s1, TestStructure s2)
        {
            Assert.AreEqual(s1.Uint64Val, s2.Uint64Val);
            Assert.AreEqual(s1.StringVal, s2.StringVal);
            Assert.AreEqual(s1.IntPtrVal, s2.IntPtrVal);
            Assert.AreEqual(s1.Uint32Val, s2.Uint32Val);
            Assert.AreEqual(s1.BoolVal, s2.BoolVal);
            Assert.AreEqual(s1.EnumVal, s2.EnumVal);
        }

        [Test]
        public void TestManualMarshalPtrToString()
        {
            IntPtr pTestString = IntPtr.Zero;
            try
            {
                string testString = "hello, my name is Test!";
                pTestString = MarshalUtils.StringToPtr(testString);
                StringStructure stringStructure = new StringStructure
                {
                    SimpleString = pTestString
                };

                OtherStruct otherStruct = new OtherStruct
                {
                    OtherInt = 42,
                    OtherString = "blablabla"
                };

                StringClass stringClass = new StringClass
                {
                    OtherField = otherStruct
                };

                Assert.Throws<ArgumentNullException>(()=>
                    MarshalUtils.AllPtrsToStrings<StringStructure, StringClass>(
                        stringStructure,
                        null));
                MarshalUtils.AllPtrsToStrings(stringStructure, stringClass);
                Assert.NotNull(stringClass.SimpleString);
                Assert.AreEqual(stringClass.SimpleString, testString);
                Assert.AreEqual(stringClass.OtherField.OtherInt, otherStruct.OtherInt);
                Assert.AreEqual(stringClass.OtherField.OtherString, otherStruct.OtherString);
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(pTestString);
            }
        }

        [Test]
        public void TestInvalidManualMarshalPtrToString()
        {
            IntPtr pTestString = IntPtr.Zero;
            try
            {
                string testString = "hello, my name is Test!";
                pTestString = MarshalUtils.StringToPtr(testString);
                InvalidStringStructure stringStructure = new InvalidStringStructure
                {
                    SimpleString = (int)pTestString
                };

                StringClass stringClass = new StringClass();
                Assert.Throws<InvalidOperationException>(()=>
                        MarshalUtils.AllPtrsToStrings(stringStructure, stringClass));
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(pTestString);
            }
        }

        [Test]
        public void TestManualMarshalStringToPtr()
        {
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                string testString = "hello, my name is Test!";
                StringClass stringClass = new StringClass
                {
                    SimpleString = testString
                };

                OtherStruct otherStruct = new OtherStruct
                {
                    OtherInt = 42,
                    OtherString = "blablabla"
                };

                StringStructure stringStructure = new StringStructure
                {
                    OtherField = otherStruct
                };
                
                Assert.Throws<ArgumentNullException>(()=>
                     MarshalUtils.AllStringsToPtrs<StringClass, StringStructure>(
                         null,
                         ref stringStructure,
                         allocatedPointers));

                Assert.Throws<ArgumentNullException>(()=>
                    MarshalUtils.AllStringsToPtrs(
                        stringClass,
                        ref stringStructure,
                        null));

                MarshalUtils.AllStringsToPtrs(
                    stringClass,
                    ref stringStructure,
                    allocatedPointers);
               
                string restoredString = MarshalUtils.PtrToString(stringStructure.SimpleString);
                Assert.AreEqual(stringClass.SimpleString, restoredString);
                Assert.AreEqual(1, allocatedPointers.Count);
                Assert.AreEqual(stringStructure.OtherField.OtherInt, otherStruct.OtherInt);
                Assert.AreEqual(stringStructure.OtherField.OtherString, otherStruct.OtherString);
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
            }
        }

        [Test]
        public void TestInvalidManualMarshalStringToPtr()
        {
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                string testString = "hello, my name is Test!";
                InvalidStringClass stringClass = new InvalidStringClass
                {
                    SimpleString = testString.ToArray()
                };

                StringStructure stringStructure = new StringStructure();
                Assert.Throws<InvalidOperationException>(()=>
                    MarshalUtils.AllStringsToPtrs(
                        stringClass,
                        ref stringStructure,
                        allocatedPointers));
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
            }
        }

        private struct OtherStruct
        {
            internal int OtherInt;
            internal string OtherString;
        }

        private struct StringStructure
        {
            internal OtherStruct OtherField;
            [ManualMarshalPtrToString]
            internal IntPtr SimpleString;
        }

        private struct InvalidStringStructure
        {
            [ManualMarshalPtrToString]
            internal int SimpleString;
        }

        private class StringClass
        {
            internal OtherStruct OtherField { get; set; }
            [ManualMarshalStringToPtr]
            internal string SimpleString { get; set; }
        }

        private class InvalidStringClass
        {
            [ManualMarshalStringToPtr]
            internal char[] SimpleString { get; set; }
        }

        private struct TestStructure
        {
            [MarshalAs(UnmanagedType.U8)]
            internal UInt64 Uint64Val;

            [MarshalAs(UnmanagedType.LPStr)]
            internal string StringVal;

            internal IntPtr IntPtrVal;

            [MarshalAs(UnmanagedType.U4)]
            internal UInt32 Uint32Val;

            [MarshalAs(UnmanagedType.I1)]
            internal bool BoolVal;

            internal TestEnum EnumVal;
        }

        private enum TestEnum
        {
            One = 0,
            Two = 1,
            Three = 3
        }
    }
}