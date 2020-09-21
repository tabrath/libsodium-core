using System.Text;

using NUnit.Framework;

using Sodium;

namespace Tests
{
    /// <summary>Tests for the SecretBox class</summary>
    [TestFixture]
    public class SecretBoxTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(32, SecretBox.GenerateKey().Length);
        }

        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateNonce()
        {
            Assert.AreEqual(24, SecretBox.GenerateNonce().Length);
        }

        /// <summary>Does SecretBox.Create() return the expected value?</summary>
        [Test]
        public void CreateSecretBox()
        {
            var expected = Utilities.HexToBinary("b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164");
            var actual = SecretBox.Create(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretBox.open() return the expected value?</summary>
        [Test]
        public void OpenSecretBox()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(SecretBox.Open(
              Utilities.HexToBinary("b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));

            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Does SecretBox.open() return the expected value?</summary>
        [Test]
        public void OpenSecretBoxWithPadding()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(SecretBox.Open(
              Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));

            Assert.AreEqual(EXPECTED, actual);
        }

        /// <summary>Does SecretBox.CreateDetached() and SecretBox.OpenDetached() work?</summary>
        [Test]
        public void DetachedSecretBox()
        {
            var expected = Utilities.HexToBinary("4164616d2043617564696c6c");
            var actual = SecretBox.CreateDetached(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            var clear = SecretBox.OpenDetached(actual.CipherText, actual.Mac,
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.AreEqual(clear, expected);
        }

        /// <summary>Does SecretBox.Create() return the expected value?</summary>
        [Test]
        public void Xchacha20Poly1305CreateSecretBox()
        {
            var expected = Utilities.HexToBinary("3bc2fce4a5a78ed04d5aadfcf5df9ad415792227a0c1ba79b87fd165");
            var actual = SecretBox.Xchacha20Poly1305Create(
              Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does SecretBox.Xchacha20Poly1305Open() return the expected value?</summary>
        [Test]
        public void Xchacha20Poly1305OpenSecretBox()
        {
            const string EXPECTED = "Adam Caudill";
            var actual = Encoding.UTF8.GetString(SecretBox.Xchacha20Poly1305Open(
              Utilities.HexToBinary("3bc2fce4a5a78ed04d5aadfcf5df9ad415792227a0c1ba79b87fd165"),
              Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
              Encoding.UTF8.GetBytes("12345678901234567890123456789012")));

            Assert.AreEqual(EXPECTED, actual);
        }

        ///// <summary>Does SecretBox.Xchacha20Poly1305Open() return the expected value?</summary>
        //[Test]
        //public void Xchacha20Poly1305OpenSecretBoxWithPadding()
        //{
        //    // todo - please review this! i'm not sure if this test is needed also for xchacha-version

        //    const string EXPECTED = "Adam Caudill";
        //    var actual = Encoding.UTF8.GetString(SecretBox.Xchacha20Poly1305Open(
        //        Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
        //        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        //        Encoding.UTF8.GetBytes("12345678901234567890123456789012")));

        //    Assert.AreEqual(EXPECTED, actual);
        //}

        /// <summary>Does SecretBox.CreateDetached() and SecretBox.OpenDetached() work?</summary>
        [Test]
        public void Xchacha20Poly1305DetachedSecretBox()
        {
            var nonce = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX");
            var key = Encoding.UTF8.GetBytes("12345678901234567890123456789012");
            const string originalMessage = "Adam Caudill";

            var detachedBox = SecretBox.Xchacha20Poly1305CreateDetached(Encoding.UTF8.GetBytes(originalMessage), nonce, key);

            var decryptedMessage = Encoding.UTF8.GetString(
                SecretBox.Xchacha20Poly1305OpenDetached(detachedBox.CipherText, detachedBox.Mac, nonce, key));

            Assert.AreEqual(originalMessage, decryptedMessage);
        }
    }
}
