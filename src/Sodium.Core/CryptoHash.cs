using System;
using System.Text;

namespace Sodium
{
    /// <summary>Provides hashing via selected primitive.</summary>
    public class CryptoHash
    {
        //pulled from various #define statements; may break with new versions
        private const int SHA512_BYTES = 64;
        private const int SHA256_BYTES = 32;

        #region Default

        /// <summary>Hashes a string using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Hash(string message)
        {
            var span = new Span<byte>(new byte[SHA512_BYTES]);
            Hash(message.AsSpan(), span);
            return span.ToArray();
        }

        /// <summary>Hashes a string using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static void Hash(string message, Span<byte> target)
        {
            Hash(message.AsSpan(), target);
        }

        /// <summary>Hashes a byte array using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Hash(byte[] message)
        {
            var span = new Span<byte>(new byte[SHA512_BYTES]);
            Hash(message, span);
            return span.ToArray();
        }

        /// <summary>Hashes a byte span using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns></returns>
        public static void Hash(ReadOnlySpan<byte> message, Span<byte> target)
        {
            unsafe
            {
                fixed (byte* b = &target.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        SodiumLibrary.crypto_hash(b, m, message.Length);
                    }
                }
            }
        }

        /// <summary>Hashes a byte span using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns></returns>
        public static void Hash(ReadOnlySpan<char> message, Span<byte> target)
        {
            var encoding = Encoding.UTF8;

            unsafe
            {
                fixed (char* c = &message.GetPinnableReference())
                {
                    var minLength = encoding.GetByteCount(c, message.Length);

                    var temp = Utilities.Pool.Rent(minLength);

                    var sized = temp.AsSpan().Slice(0, minLength);

                    fixed (byte* b = &sized.GetPinnableReference())
                    {
                        try
                        {
                            encoding.GetBytes(c, message.Length, b, minLength);

                            Hash(sized, target);
                        }
                        finally
                        {
                            Utilities.Pool.Return(temp);
                        }
                    }
                }
            }
        }

        #endregion

        #region SHA-512

        /// <summary>Hashes a string using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Sha512(string message)
        {
            var span = new Span<byte>(new byte[SHA512_BYTES]);
            Sha512(message.AsSpan(), span);
            return span.ToArray();
        }

        /// <summary>Hashes a string using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static void Sha512(string message, Span<byte> target)
        {
            Sha512(message.AsSpan(), target);
        }

        /// <summary>Hashes a byte array using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Sha512(byte[] message)
        {
            var span = new Span<byte>(new byte[SHA512_BYTES]);
            Sha512(message, span);
            return span.ToArray();
        }

        /// <summary>Hashes a byte span using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns></returns>
        public static void Sha512(ReadOnlySpan<char> message, Span<byte> target)
        {
            message.WithMessageSpan(Encoding.UTF8, target, m =>
            {
                unsafe
                {
                    SodiumLibrary.crypto_hash_sha512(m.Ref1, m.Ptr, m.Length);
                }
            });
        }

        /// <summary>Hashes a byte span using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns></returns>
        public static void Sha512(ReadOnlySpan<byte> message, Span<byte> target)
        {
            unsafe
            {
                fixed (byte* b = &target.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        SodiumLibrary.crypto_hash_sha512(b, m, message.Length);
                    }
                }
            }
        }

        #endregion

        #region SHA-256

        /// <summary>Hashes a string using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Sha256(string message)
        {
            var span = new Span<byte>(new byte[SHA256_BYTES]);
            Sha256(message.AsSpan(), span);
            return span.ToArray();
        }

        /// <summary>Hashes a string using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static void Sha256(string message, Span<byte> target)
        {
            Sha256(message.AsSpan(), target);
        }

        /// <summary>Hashes a byte array using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Sha256(byte[] message)
        {
            var span = new Span<byte>(new byte[SHA256_BYTES]);
            Sha256(message, span);
            return span.ToArray();
        }

        /// <summary>Hashes a byte span using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns></returns>
        public static void Sha256(ReadOnlySpan<char> message, Span<byte> target)
        {
            message.WithMessageSpan(Encoding.UTF8, target, m =>
            {
                unsafe
                {
                    SodiumLibrary.crypto_hash_sha256(m.Ref1, m.Ptr, m.Length);
                }
            });
        }

        /// <summary>Hashes a byte span using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <param name="target">The byte span to write the resulting hash to.</param>
        /// <returns></returns>
        public static void Sha256(ReadOnlySpan<byte> message, Span<byte> target)
        {
            unsafe
            {
                fixed (byte* b = &target.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        SodiumLibrary.crypto_hash_sha256(b, m, message.Length);
                    }
                }
            }
        }

        #endregion
    }
}
