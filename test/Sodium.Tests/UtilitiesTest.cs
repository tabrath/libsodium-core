using System;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    /// <summary>Tests for the Utilities class</summary>
    [TestFixture]
    public class UtilitiesTest
    {

        /// <summary>A simple test for validating the hex method.</summary>
        [Test]
        public void HexToBinaryTest()
        {
            const string ACTUAL = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
            const string ACTUAL_UPPER = "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A";
            var expected = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var binSodiumLower = Utilities.HexToBinary(ACTUAL);
            var binSodiumUpper = Utilities.HexToBinary(ACTUAL_UPPER);

            Assert.AreEqual(expected, binSodiumLower);
            Assert.AreEqual(expected, binSodiumUpper);
        }

        /// <summary>Test the hex decoding with some colons.</summary>
        [Test]
        public void HexToBinaryColonTest()
        {
            const string ACTUAL =
              "77:07:6d:0a:73:18:a5:7d:3c:16:c1:72:51:b2:66:45:df:4c:2f:87:eb:c0:99:2a:b1:77:fb:a5:1d:b9:2c:2a";
            const string ACTUAL_UPPER =
              "77:07:6D:0A:73:18:A5:7D:3C:16:C1:72:51:B2:66:45:DF:4C:2F:87:EB:C0:99:2A:B1:77:FB:A5:1D:B9:2C:2A";
            var expected = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var binSodiumLower = Utilities.HexToBinary(ACTUAL);
            var binSodiumUpper = Utilities.HexToBinary(ACTUAL_UPPER);

            Assert.AreEqual(expected, binSodiumLower);
            Assert.AreEqual(expected, binSodiumUpper);
        }

        /// <summary>Test the hex decoding with some hyphens.</summary>
        [Test]
        public void HexToBinaryHyphenTest()
        {
            const string ACTUAL =
              "77-07-6d-0a-73-18-a5-7d-3c-16-c1-72-51-b2-66-45-df-4c-2f-87-eb-c0-99-2a-b1-77-fb-a5-1d-b9-2c-2a";
            const string ACTUAL_UPPER =
              "77-07-6D-0A-73-18-A5-7D-3C-16-C1-72-51-B2-66-45-DF-4C-2F-87-EB-C0-99-2A-B1-77-FB-A5-1D-B9-2C-2A";
            var expected = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var binSodiumLower = Utilities.HexToBinary(ACTUAL);
            var binSodiumUpper = Utilities.HexToBinary(ACTUAL_UPPER);

            Assert.AreEqual(expected, binSodiumLower);
            Assert.AreEqual(expected, binSodiumUpper);
        }

        /// <summary>Test the hex decoding with some spaces.</summary>
        [Test]
        public void HexToBinarySpaceTest()
        {
            const string ACTUAL =
              "77 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45 df 4c 2f 87 eb c0 99 2a b1 77 fb a5 1d b9 2c 2a";
            const string ACTUAL_UPPER =
              "77 07 6D 0A 73 18 A5 7D 3C 16 C1 72 51 B2 66 45 DF 4C 2F 87 EB C0 99 2A B1 77 FB A5 1D B9 2C 2A";
            var expected = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var binSodiumLower = Utilities.HexToBinary(ACTUAL);
            var binSodiumUpper = Utilities.HexToBinary(ACTUAL_UPPER);

            Assert.AreEqual(expected, binSodiumLower);
            Assert.AreEqual(expected, binSodiumUpper);
        }

        /// <summary>A simple test for validating the libsodium wrapper.</summary>
        [Test]
        public void BinaryToHexPatternsTest()
        {
            const string EXPECTED_NULLS = "0000000000000000";
            const string EXPECTED_FFS = "ffffffffffffffff";
            const string EXPECTED_FLIP = "0f0f0f0f0f0f0f0f";

            var nulls = new byte[]
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            var ffs = new byte[]
            {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            };
            var flips = new byte[]
            {
                0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
            };

            var encodedNulls = Utilities.BinaryToHex(nulls);
            var encodedFfs = Utilities.BinaryToHex(ffs);
            var encodedFlips = Utilities.BinaryToHex(flips);

            Assert.AreEqual(EXPECTED_NULLS, encodedNulls);
            Assert.AreEqual(EXPECTED_FFS, encodedFfs);
            Assert.AreEqual(EXPECTED_FLIP, encodedFlips);
        }

        /// <summary>A simple test for validating the two hex methods.</summary>
        [Test]
        public void BinaryToHexTest()
        {
            const string EXPECTED = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
            const string EXPECTED_UPPER = "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A";
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var hexSharpLower = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.None);
            var hexSharpUpper = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.None, Utilities.HexCase.Upper);
            var hexSodium = Utilities.BinaryToHex(aliceSk);
            var hexSodiumUnsafe = Utilities.BinaryToHex(new ReadOnlySpan<byte>(aliceSk, 0, aliceSk.Length));

            Assert.AreEqual(EXPECTED, hexSharpLower);
            Assert.AreEqual(EXPECTED_UPPER, hexSharpUpper);
            Assert.AreEqual(EXPECTED, hexSodium);
            Assert.AreEqual(EXPECTED, hexSodiumUnsafe);
        }

        /// <summary>Test the hex encoding with some colons.</summary>
        [Test]
        public void BinaryToHexColonTest()
        {
            const string EXPECTED =
              "77:07:6d:0a:73:18:a5:7d:3c:16:c1:72:51:b2:66:45:df:4c:2f:87:eb:c0:99:2a:b1:77:fb:a5:1d:b9:2c:2a";
            const string EXPECTED_UPPER =
              "77:07:6D:0A:73:18:A5:7D:3C:16:C1:72:51:B2:66:45:DF:4C:2F:87:EB:C0:99:2A:B1:77:FB:A5:1D:B9:2C:2A";
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var hexSharpLower = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.Colon);
            var hexSharpUpper = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.Colon, Utilities.HexCase.Upper);

            Assert.AreEqual(EXPECTED, hexSharpLower);
            Assert.AreEqual(EXPECTED_UPPER, hexSharpUpper);
        }

        /// <summary>Test the hex encoding with some hyphens.</summary>
        [Test]
        public void BinaryToHexHyphenTest()
        {
            const string EXPECTED =
              "77-07-6d-0a-73-18-a5-7d-3c-16-c1-72-51-b2-66-45-df-4c-2f-87-eb-c0-99-2a-b1-77-fb-a5-1d-b9-2c-2a";
            const string EXPECTED_UPPER =
              "77-07-6D-0A-73-18-A5-7D-3C-16-C1-72-51-B2-66-45-DF-4C-2F-87-EB-C0-99-2A-B1-77-FB-A5-1D-B9-2C-2A";
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var hexSharpLower = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.Hyphen);
            var hexSharpUpper = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.Hyphen, Utilities.HexCase.Upper);

            Assert.AreEqual(EXPECTED, hexSharpLower);
            Assert.AreEqual(EXPECTED_UPPER, hexSharpUpper);
        }

        /// <summary>Test the hex encoding with some spaces.</summary>
        [Test]
        public void BinaryToHexSpaceTest()
        {
            const string EXPECTED =
              "77 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45 df 4c 2f 87 eb c0 99 2a b1 77 fb a5 1d b9 2c 2a";
            const string EXPECTED_UPPER =
              "77 07 6D 0A 73 18 A5 7D 3C 16 C1 72 51 B2 66 45 DF 4C 2F 87 EB C0 99 2A B1 77 FB A5 1D B9 2C 2A";
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var hexSharpLower = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.Space);
            var hexSharpUpper = Utilities.BinaryToHex(aliceSk, Utilities.HexFormat.Space, Utilities.HexCase.Upper);

            Assert.AreEqual(EXPECTED, hexSharpLower);
            Assert.AreEqual(EXPECTED_UPPER, hexSharpUpper);
        }

        [Test]
        public void BinaryToBase64OriginalTest()
        {
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var base64 = Utilities.BinaryToBase64(aliceSk);
            var decrypted = Utilities.Base64ToBinary(base64, null);
            Assert.AreEqual(aliceSk, decrypted);
        }

        [Test]
        public void BinaryToBase64OriginalNoPaddingTest()
        {
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var base64 = Utilities.BinaryToBase64(aliceSk, Utilities.Base64Variant.OriginalNoPadding);
            var decrypted = Utilities.Base64ToBinary(base64, null, Utilities.Base64Variant.OriginalNoPadding);
            Assert.AreEqual(aliceSk, decrypted);
        }

        [Test]
        public void BinaryToBase64UrlSafeTest()
        {
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var base64 = Utilities.BinaryToBase64(aliceSk, Utilities.Base64Variant.UrlSafe);
            var decrypted = Utilities.Base64ToBinary(base64, null, Utilities.Base64Variant.UrlSafe);
            Assert.AreEqual(aliceSk, decrypted);
        }

        [Test]
        public void BinaryToBase64UrlSafeNoPaddingTest()
        {
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            var base64 = Utilities.BinaryToBase64(aliceSk, Utilities.Base64Variant.UrlSafeNoPadding);
            var decrypted = Utilities.Base64ToBinary(base64, null, Utilities.Base64Variant.UrlSafeNoPadding);
            Assert.AreEqual(aliceSk, decrypted);
        }

        [Test]
        public void BinaryToBase64IgnoreSpaceTest()
        {
            var aliceSk = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };

            string base64 = Utilities.BinaryToBase64(aliceSk);
            string editedBase64 = "";
            foreach (char item in base64)
            {
                editedBase64 += $"{item} ";
            }

            var decrypted = Utilities.Base64ToBinary(editedBase64, " ");
            Assert.AreEqual(aliceSk, decrypted);
        }

        [Test]
        public void BinaryToBase64EmptyByteArrTest()
        {
            var emptyArr = new byte[] { };
            string base64 = Utilities.BinaryToBase64(emptyArr);
            var decrypted = Utilities.Base64ToBinary(base64, " ");
            Assert.IsEmpty(decrypted);
        }

        /// <summary>Test the increment implementation.</summary>
        [Test]
        public void IncrementTest()
        {
            const string nonceHex = "76368325eb272b0cde06fab2f010b3f5ecd5a805709e9505";
            var incrementedNonce = Utilities.Increment(Utilities.HexToBinary(nonceHex));
            Assert.AreNotEqual(nonceHex, Utilities.BinaryToHex(incrementedNonce));
        }

        /// <summary>Test the sodium_compare implementation.</summary>
        [Test]
        public void CompareTest()
        {
            var a = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a
            };

            var b = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            };

            var c = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a
            };

            var d = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c
            };

            Assert.AreEqual(false, Utilities.Compare(a, b));
            Assert.AreEqual(true, Utilities.Compare(a, c));
            Assert.AreEqual(false, Utilities.Compare(a, d));
            Assert.AreEqual(false, Utilities.Compare(d, b));
        }
    }
}
