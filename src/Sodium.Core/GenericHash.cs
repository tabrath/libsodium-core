using System;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>
    /// Multipurpose hash function.
    /// </summary>
    public partial class GenericHash
    {
        //this was pulled from the headers; should be more dynamic
        private const int BYTES_MIN = 16;
        private const int BYTES_MAX = 64;
        private const int KEY_BYTES_MIN = 16;
        private const int KEY_BYTES_MAX = 64;
        private const int OUT_BYTES = 64;
        private const int SALT_BYTES = 16;
        private const int PERSONAL_BYTES = 16;

        /// <summary>Generates a random 64 byte key.</summary>
        /// <returns>Returns a byte array with 64 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SodiumCore.GetRandomBytes(KEY_BYTES_MAX);
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, string key, int bytes)
        {
            var buffer = new byte[bytes];
            Hash(message.AsSpan(), key.AsSpan(), bytes, buffer);
            return buffer;
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, byte[] key, int bytes)
        {
            var buffer = new byte[bytes];
            Hash(message.AsSpan(), key, bytes, buffer);
            return buffer;
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, byte[] key, int bytes)
        {
            var buffer = new byte[bytes];
            Hash(message, key, bytes, buffer);
            return buffer;
        }

        /// <summary>Generates a hash based on a key, salt and personal strings</summary>
        /// <returns><c>byte</c> hashed message</returns>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] HashSaltPersonal(string message, string key, string salt, string personal, int bytes = OUT_BYTES)
        {
            var buffer = new byte[bytes];
            HashSaltPersonal(message, key, salt, personal, buffer);
            return buffer;
        }

        /// <summary>Generates a hash based on a key, salt and personal bytes</summary>
        /// <returns><c>byte</c> hashed message</returns>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal string.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] HashSaltPersonal(byte[] message, byte[] key, byte[] salt, byte[] personal, int bytes = OUT_BYTES)
        {
            var buffer = new byte[bytes];
            HashSaltPersonal(message, key, salt, personal, buffer);
            return buffer;
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static void Hash(ReadOnlySpan<char> message, ReadOnlySpan<byte> key, int bytes, Span<byte> target)
        {
            var encoding = Encoding.UTF8;

            unsafe
            {
                fixed (char* mc = &message.GetPinnableReference())
                {
                    var mMinLength = encoding.GetByteCount(mc, message.Length);
                    var mTemp = Utilities.Pool.Rent(mMinLength);
                    try
                    {
                        var m = mTemp.AsSpan().Slice(0, mMinLength);

                        fixed (byte* mSized = &m.GetPinnableReference())
                        {
                            encoding.GetBytes(mc, message.Length, mSized, mMinLength);
                        }

                        Hash(m, key, bytes, target);
                    }
                    finally
                    {
                        Utilities.Pool.Return(mTemp);
                    }
                }
            }
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static void Hash(ReadOnlySpan<char> message, ReadOnlySpan<char> key, int bytes, Span<byte> target)
        {
            var encoding = Encoding.UTF8;

            unsafe
            {
                fixed (char* mc = &message.GetPinnableReference())
                {
                    fixed (char* kc = &key.GetPinnableReference())
                    {
                        var mMinLength = encoding.GetByteCount(mc, message.Length);
                        var kMinLength = encoding.GetByteCount(kc, key.Length);

                        var mTemp = Utilities.Pool.Rent(mMinLength);
                        var kTemp = Utilities.Pool.Rent(kMinLength);

                        try
                        {
                            var m = mTemp.AsSpan().Slice(0, mMinLength);
                            var k = kTemp.AsSpan().Slice(0, kMinLength);

                            fixed (byte* mSized = &m.GetPinnableReference())
                            {
                                encoding.GetBytes(mc, message.Length, mSized, mMinLength);
                            }
                            fixed (byte* kSized = &k.GetPinnableReference())
                            {
                                encoding.GetBytes(kc, key.Length, kSized, kMinLength);
                            }

                            Hash(m, k, bytes, target);
                        }
                        finally
                        {
                            Utilities.Pool.Return(mTemp);
                            Utilities.Pool.Return(kTemp);
                        }
                    }
                }
            }
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static void Hash(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, int bytes, Span<byte> target)
        {
            //validate the length of the key
            int keyLength;
            if (key != null)
            {
                if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                {
                    throw new KeyOutOfRangeException(string.Format("key must be between {0} and {1} bytes in length.",
                      KEY_BYTES_MIN, KEY_BYTES_MAX));
                }

                keyLength = key.Length;
            }
            else
            {
                key = new byte[0];
                keyLength = 0;
            }

            //validate output length
            if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                throw new BytesOutOfRangeException("bytes", bytes,
                  string.Format("bytes must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));

            var buffer = new byte[bytes];

            unsafe
            {
                fixed (byte* b = &target.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        fixed (byte* k = &key.GetPinnableReference())
                        {
                            SodiumLibrary.crypto_generichash(b, buffer.Length, m, message.Length, k, keyLength);
                        }
                    }
                }
            }
        }

        /// <summary>Generates a hash based on a key, salt and personal strings</summary>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static void HashSaltPersonal(string message, string key, string salt, string personal, Span<byte> target)
        {
            HashSaltPersonal(message.AsSpan(), key.AsSpan(), salt.AsSpan(), personal.AsSpan(), target);
        }

        /// <summary>Generates a hash based on a key, salt and personal strings</summary>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static void HashSaltPersonal(ReadOnlySpan<char> message, ReadOnlySpan<char> key, ReadOnlySpan<char> salt, ReadOnlySpan<char> personal, Span<byte> target)
        {
            var encoding = Encoding.UTF8;

            unsafe
            {
                fixed (char* mc = &message.GetPinnableReference())
                {
                    fixed (char* kc = &key.GetPinnableReference())
                    {
                        fixed (char* sc = &salt.GetPinnableReference())
                        {
                            fixed (char* pc = &personal.GetPinnableReference())
                            {
                                var mLength = encoding.GetByteCount(mc, message.Length);
                                var kMinLength = encoding.GetByteCount(kc, key.Length);
                                var sMinLength = encoding.GetByteCount(sc, salt.Length);
                                var pMinLength = encoding.GetByteCount(pc, personal.Length);

                                var mTemp = Utilities.Pool.Rent(mLength);
                                var kTemp = Utilities.Pool.Rent(kMinLength);
                                var sTemp = Utilities.Pool.Rent(sMinLength);
                                var pTemp = Utilities.Pool.Rent(pMinLength);

                                try
                                {
                                    var m = mTemp.AsSpan().Slice(0, mLength);
                                    var k = kTemp.AsSpan().Slice(0, kMinLength);
                                    var s = sTemp.AsSpan().Slice(0, sMinLength);
                                    var p = pTemp.AsSpan().Slice(0, pMinLength);

                                    fixed (byte* mSized = &m.GetPinnableReference())
                                    {
                                        encoding.GetBytes(mc, message.Length, mSized, mLength);
                                    }
                                    fixed (byte* kSized = &k.GetPinnableReference())
                                    {
                                        encoding.GetBytes(kc, key.Length, kSized, kMinLength);
                                    }
                                    fixed (byte* sSized = &s.GetPinnableReference())
                                    {
                                        encoding.GetBytes(sc, salt.Length, sSized, sMinLength);
                                    }
                                    fixed (byte* pSized = &p.GetPinnableReference())
                                    {
                                        encoding.GetBytes(pc, personal.Length, pSized, pMinLength);
                                    }

                                    HashSaltPersonal(m, k, s, p, target);
                                }
                                finally
                                {
                                    Utilities.Pool.Return(mTemp);
                                    Utilities.Pool.Return(kTemp);
                                    Utilities.Pool.Return(sTemp);
                                    Utilities.Pool.Return(pTemp);
                                }
                            }
                        }

                    }
                }
            }
        }

        /// <summary>Generates a hash based on a key, salt and personal bytes</summary>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal string.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static void HashSaltPersonal(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt,
          ReadOnlySpan<byte> personal, Span<byte> target)
        {
            if (message == null)
                throw new ArgumentNullException("message", "Message cannot be null");

            if (salt == null)
                throw new ArgumentNullException("salt", "Salt cannot be null");

            if (personal == null)
                throw new ArgumentNullException("personal", "Personal string cannot be null");

            if (key != null && (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN))
                throw new KeyOutOfRangeException(string.Format("key must be between {0} and {1} bytes in length.", KEY_BYTES_MIN, KEY_BYTES_MAX));

            if (key == null)
                key = new byte[0];

            if (salt.Length != SALT_BYTES)
                throw new SaltOutOfRangeException(string.Format("Salt must be {0} bytes in length.", SALT_BYTES));

            if (personal.Length != PERSONAL_BYTES)
                throw new PersonalOutOfRangeException(string.Format("Personal bytes must be {0} bytes in length.", PERSONAL_BYTES));

            //validate output length
            if (target.Length > BYTES_MAX || target.Length < BYTES_MIN)
                throw new BytesOutOfRangeException("target", target.Length,
                  string.Format("target must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));

            unsafe
            {
                fixed (byte* b = &target.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        fixed (byte* k = &key.GetPinnableReference())
                        {
                            fixed (byte* s = &salt.GetPinnableReference())
                            {
                                fixed (byte* p = &personal.GetPinnableReference())
                                {
                                    var bufferLength = target.Length;
                                    long messageLength = message.Length;
                                    var keyLength = key.Length;

                                    SodiumLibrary.crypto_generichash_blake2b_salt_personal(b, bufferLength, m, messageLength, k,
                                      keyLength, s, p);
                                };
                            }
                        }
                    }
                }
            }
        }
    }
}
