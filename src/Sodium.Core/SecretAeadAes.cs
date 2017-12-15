using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Authenticated Encryption with Additional Data using AES-GCM.
    /// Only supported on modern x86/x64 processors.</summary>
    /// <remarks>See here for more information: https://download.libsodium.org/doc/advanced/aes-256-gcm.html </remarks>
    public static class SecretAeadAes
    {
        private const int KEYBYTES = 32;
        private const int NPUBBYTES = 12;
        private const int ABYTES = 16;

        /// <summary>Detect if the current CPU supports the required instructions (SSSE3, aesni, pcmul).</summary>
        /// <returns><c>true</c> if the CPU supports the necessary instructions, otherwise <c>false</c></returns>
        /// <remarks>Use <see cref="SecretAead"/> if portability is required.</remarks>
        public static bool IsAvailable()
        {
            SodiumCore.Init();

            return SodiumLibrary.crypto_aead_aes256gcm_is_available() != 0;
        }

        /// <summary>Generates a random 12 byte nonce.</summary>
        /// <returns>Returns a byte array with 12 random bytes.</returns>
        public static byte[] GenerateNonce() => SodiumCore.GetRandomBytes(NPUBBYTES);

        /// <summary>
        /// Encrypts a message with an authentication tag and additional data using AES-GCM.
        /// </summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
        /// <returns>The encrypted message with additional data.</returns>
        /// <remarks>The nonce should never ever be reused with the same key.</remarks>
        /// <remarks>The recommended way to generate it is to use GenerateNonce() for the first message, and increment it for each subsequent message using the same key.</remarks>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="AdditionalDataOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            //additionalData can be null
            if (additionalData == null)
                additionalData = new byte[0x00];

            //validate the length of the key
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEYBYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NPUBBYTES} bytes in length.");

            //validate the length of the additionalData
            if (additionalData.Length > ABYTES || additionalData.Length < 0)
                throw new AdditionalDataOutOfRangeException($"additionalData must be between {0} and {ABYTES} bytes in length.");

            var cipher = new byte[message.Length + ABYTES];
            var bin = Marshal.AllocHGlobal(cipher.Length);

            var ret = SodiumLibrary.crypto_aead_aes256gcm_encrypt(bin, out var cipherLength, message, message.Length, additionalData, additionalData.Length, null, nonce, key);

            Marshal.Copy(bin, cipher, 0, (int)cipherLength);
            Marshal.FreeHGlobal(bin);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            if (cipher.Length == cipherLength)
                return cipher;

            //remove the trailing nulls from the array
            var tmp = new byte[cipherLength];
            Array.Copy(cipher, 0, tmp, 0, (int)cipherLength);

            return tmp;
        }

        /// <summary>
        /// Decrypts a cipher with an authentication tag and additional data using AES-GCM.
        /// </summary>
        /// <param name="cipher">The cipher to be decrypted.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
        /// <returns>The decrypted cipher.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="AdditionalDataOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] cipher, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            //additionalData can be null
            if (additionalData == null)
                additionalData = new byte[0x00];

            //validate the length of the key
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEYBYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NPUBBYTES} bytes in length.");

            //validate the length of the additionalData
            if (additionalData.Length > ABYTES || additionalData.Length < 0)
                throw new AdditionalDataOutOfRangeException($"additionalData must be between {0} and {ABYTES} bytes in length.");

            var message = new byte[cipher.Length - ABYTES];
            var bin = Marshal.AllocHGlobal(message.Length);

            var ret = SodiumLibrary.crypto_aead_aes256gcm_decrypt(bin, out var messageLength, null, cipher, cipher.Length, additionalData, additionalData.Length, nonce, key);

            Marshal.Copy(bin, message, 0, (int)messageLength);
            Marshal.FreeHGlobal(bin);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            if (message.Length == messageLength)
                return message;

            //remove the trailing nulls from the array
            var tmp = new byte[messageLength];
            Array.Copy(message, 0, tmp, 0, (int)messageLength);

            return tmp;
        }
    }
}
