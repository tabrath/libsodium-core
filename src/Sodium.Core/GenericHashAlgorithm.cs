using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    public partial class GenericHash
    {
        /// <summary>
        /// Blake2b implementation of HashAlgorithm suitable for hashing streams.
        /// </summary>
        public class GenericHashAlgorithm : HashAlgorithm
        {
            private IntPtr hashStatePtr;
            private byte[] key;
            private int bytes;

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(string key, int bytes) : this(Encoding.UTF8.GetBytes(key), bytes) { }

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(byte[] key, int bytes)
            {
                this.hashStatePtr = Marshal.AllocHGlobal(Marshal.SizeOf<SodiumLibrary.HashState>());

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

                this.key = key;

                //validate output length
                if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                    throw new BytesOutOfRangeException("bytes", bytes,
                      string.Format("bytes must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));

                this.bytes = bytes;

                Initialize();
            }

            ~GenericHashAlgorithm()
            {
                Marshal.FreeHGlobal(hashStatePtr);
            }

            public override void Initialize()
            {
                SodiumLibrary.crypto_generichash_init(hashStatePtr, key, key.Length, bytes);
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                byte[] subArray = new byte[cbSize];
                Array.Copy(array, ibStart, subArray, 0, cbSize);
                SodiumLibrary.crypto_generichash_update(hashStatePtr, subArray, cbSize);
            }

            protected override byte[] HashFinal()
            {
                byte[] buffer = new byte[bytes];
                SodiumLibrary.crypto_generichash_final(hashStatePtr, buffer, bytes);
                return buffer;
            }
        }
    }
}
