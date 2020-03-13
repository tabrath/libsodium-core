using NUnit.Framework;

using Sodium;

namespace Tests
{
    /// <summary>Tests for Random Bytes support</summary>
    [TestFixture]
    public class RandomBytesTest
    {
        /// <summary>Does SodiumCore.GetRandomBytes() return something</summary>
        [Test]
        public void GetRandomBytesTest()
        {
            var v16 = SodiumCore.GetRandomBytes(16);
            var v32 = SodiumCore.GetRandomBytes(32);
            var v64 = SodiumCore.GetRandomBytes(64);

            Assert.IsNotNull(v16);
            Assert.IsNotNull(v32);
            Assert.IsNotNull(v64);

            Assert.AreEqual(16U, v16.Length);
            Assert.AreEqual(32U, v32.Length);
            Assert.AreEqual(64U, v64.Length);
        }

        [Test]
        public void GetRandomBytesUnsafeTest()
        {
            var v16 = new byte[16];
            SodiumCore.GetRandomBytes(v16);

            var v32 = new byte[32];
            SodiumCore.GetRandomBytes(v32);

            var v64 = new byte[64];
            SodiumCore.GetRandomBytes(v64);

            Assert.IsNotNull(v16);
            Assert.IsNotNull(v32);
            Assert.IsNotNull(v64);

            Assert.AreEqual(16U, v16.Length);
            Assert.AreEqual(32U, v32.Length);
            Assert.AreEqual(64U, v64.Length);
        }
    }
}
