using System;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>One Time Message Authentication</summary>
    public static class OneTimeAuth
    {
        private const int KEY_BYTES = 32;
        private const int BYTES = 16;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            var buffer = new byte[KEY_BYTES];
            GenerateKey(buffer);
            return buffer;
        }

        /// <summary>Generates a random 32 byte key.</summary>
        /// <param name="target">The byte span to write the resulting key byte array with 32 random bytes.</param>
        public static void GenerateKey(Span<byte> target)
        {
            SodiumCore.GetRandomBytes(target, KEY_BYTES);
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>16 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(string message, byte[] key)
        {
            return Sign(message.AsSpan(), key.AsSpan());
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>16 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(string message, ReadOnlySpan<byte> key)
        {
            return Sign(message.AsSpan(), key);
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>16 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(ReadOnlySpan<char> message, ReadOnlySpan<byte> key)
        {
            var buffer = new byte[BYTES];
            Sign(buffer.AsSpan(), message, key);
            return buffer;
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="target">The byte span to write the resulting 16 byte authentication code to.</param>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>16 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static void Sign(Span<byte> target, ReadOnlySpan<char> message, ReadOnlySpan<byte> key)
        {
            unsafe
            {
                message.WithMessageSpan(Encoding.UTF8, target, key, m =>
                {
                    SodiumLibrary.crypto_onetimeauth(m.Ref1, m.Ptr, m.Length, m.Ref2);
                });
            }
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>16 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(byte[] message, byte[] key)
        {
            return Sign(message.AsSpan(), key.AsSpan());
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>16 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        {
            var buffer = new byte[BYTES];
            Sign(buffer.AsSpan(), message, key);
            return buffer;
        }

        /// <summary>Signs a message using Poly1305</summary>
        /// <param name="target">The byte span to write the resulting 16 byte authentication code to.</param>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static void Sign(Span<byte> target, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            unsafe
            {
                fixed (byte* b = &target.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        fixed (byte* k = &key.GetPinnableReference())
                        {
                            SodiumLibrary.crypto_onetimeauth(b, m, message.Length, k);
                        }
                    }
                }
            }
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(string message, byte[] signature, byte[] key)
        {
            return Verify(message.AsSpan(), signature.AsSpan(), key.AsSpan());
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(string message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> key)
        {
            return Verify(message.AsSpan(), signature, key);
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(ReadOnlySpan<char> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> key)
        {
            ValidateVerify(signature, key);

            var ret = -1;
            message.WithMessageSpan(Encoding.UTF8, signature, key, m =>
            {
                unsafe
                {
                    ret = SodiumLibrary.crypto_onetimeauth_verify(m.Ref1, m.Ptr, m.Length, m.Ref2);
                }
            });
            return ret == 0;
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(byte[] message, byte[] signature, byte[] key)
        {
            return Verify(message.AsSpan(), signature.AsSpan(), key.AsSpan());
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 16 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> key)
        {
            ValidateVerify(signature, key);

            unsafe
            {
                fixed (byte* s = &signature.GetPinnableReference())
                {
                    fixed (byte* m = &message.GetPinnableReference())
                    {
                        fixed (byte* k = &key.GetPinnableReference())
                        {
                            var ret = SodiumLibrary.crypto_onetimeauth_verify(s, m, message.Length, k);

                            return ret == 0;
                        }
                    }
                }
            }
        }

        private static void ValidateVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the signature
            if (signature == null || signature.Length != BYTES)
                throw new SignatureOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
                  string.Format("signature must be {0} bytes in length.", BYTES));
        }
    }
}
