using System;
using System.Security.Cryptography;
using System.Text;

using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Create and Open Secret Boxes.</summary>
    public static class SecretBox
    {
        private const int KEY_BYTES = 32;
        private const int NONCE_BYTES = 24;
        private const int MAC_BYTES = 16;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SodiumCore.GetRandomBytes(KEY_BYTES);
        }

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonce()
        {
            return SodiumCore.GetRandomBytes(NONCE_BYTES);
        }

        /// <summary>Creates a Secret Box</summary>
        /// <param name="message">Hex-encoded string to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(string message, byte[] nonce, byte[] key)
        {
            return Create(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        /// <summary>Creates a Secret Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));

            var buffer = new byte[MAC_BYTES + message.Length];
            var ret = SodiumLibrary.crypto_secretbox_easy(buffer, message, message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to create SecretBox");

            return buffer;
        }

        /// <summary>Creates detached a Secret Box</summary>
        /// <param name="message">Hex-encoded string to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox CreateDetached(string message, byte[] nonce, byte[] key)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        /// <summary>Creates detached a Secret Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox CreateDetached(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));

            var cipher = new byte[message.Length];
            var mac = new byte[MAC_BYTES];
            var ret = SodiumLibrary.crypto_secretbox_detached(cipher, mac, message, message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            return new DetachedBox(cipher, mac);
        }

        /// <summary>Opens a Secret Box</summary>
        /// <param name="cipherText">Hex-encoded string to be opened.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte nonce.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(string cipherText, byte[] nonce, byte[] key)
        {
            return Open(Utilities.HexToBinary(cipherText), nonce, key);
        }

        /// <summary>Opens a Secret Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (cipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < MAC_BYTES - 1; i++)
                {
                    if (cipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new byte[cipherText.Length - MAC_BYTES];
                    Array.Copy(cipherText, MAC_BYTES, temp, 0, cipherText.Length - MAC_BYTES);

                    cipherText = temp;
                }
            }

            var buffer = new byte[cipherText.Length - MAC_BYTES];
            var ret = SodiumLibrary.crypto_secretbox_open_easy(buffer, cipherText, cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to open SecretBox");

            return buffer;
        }

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="cipherText">Hex-encoded string to be opened</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(string cipherText, byte[] mac, byte[] nonce, byte[] key)
        {
            return OpenDetached(Utilities.HexToBinary(cipherText), mac, nonce, key);
        }

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="detached">A detached object.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(DetachedBox detached, byte[] nonce, byte[] key)
        {
            return OpenDetached(detached.CipherText, detached.Mac, nonce, key);
        }

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(byte[] cipherText, byte[] mac, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));

            //validate the length of the mac
            if (mac == null || mac.Length != MAC_BYTES)
                throw new MacOutOfRangeException("mac", (mac == null) ? 0 : mac.Length,
                  string.Format("mac must be {0} bytes in length.", MAC_BYTES));

            var buffer = new byte[cipherText.Length];
            var ret = SodiumLibrary.crypto_secretbox_open_detached(buffer, cipherText, mac, cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to open detached SecretBox");

            return buffer;
        }
        


        /// <summary>Creates a Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="message">Hex-encoded string to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305Create(string message, byte[] nonce, byte[] key) =>
            Xchacha20Poly1305Create(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Creates a Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305Create(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEY_BYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));

            var buffer = new byte[MAC_BYTES + message.Length];
            var ret = SodiumLibrary.crypto_secretbox_xchacha20poly1305_easy(buffer, message, message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to create SecretBox");

            return buffer;
        }

        /// <summary>Creates detached a Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="message">Hex-encoded string to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox Xchacha20Poly1305CreateDetached(string message, byte[] nonce, byte[] key) =>
            Xchacha20Poly1305CreateDetached(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Creates detached a Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox Xchacha20Poly1305CreateDetached(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length,
                    $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), (nonce == null) ? 0 : nonce.Length,
                    $"nonce must be {NONCE_BYTES} bytes in length.");

            var cipher = new byte[message.Length];
            var mac = new byte[MAC_BYTES];
            var ret = SodiumLibrary.crypto_secretbox_xchacha20poly1305_detached(cipher, mac, message, message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            return new DetachedBox(cipher, mac);
        }

        /// <summary>Opens a Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="cipherText">Hex-encoded string to be opened.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305Open(string cipherText, byte[] nonce, byte[] key) =>
            Xchacha20Poly1305Open(Utilities.HexToBinary(cipherText), nonce, key);


        /// <summary>Opens a Secret Box using using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305Open(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length,
                    $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), (nonce == null) ? 0 : nonce.Length,
                    $"nonce must be {NONCE_BYTES} bytes in length.");

            // todo - please review this! I'm not sure if this block is needed also for xchacha-version
            {

                ////check to see if there are MAC_BYTES of leading nulls, if so, trim.
                ////this is required due to an error in older versions.
                //if (cipherText[0] == 0)
                //{
                //    //check to see if trim is needed
                //    var trim = true;
                //    for (var i = 0; i < MAC_BYTES - 1; i++)
                //    {
                //        if (cipherText[i] != 0)
                //        {
                //            trim = false;
                //            break;
                //        }
                //    }

                //    //if the leading MAC_BYTES are null, trim it off before going on.
                //    if (trim)
                //    {
                //        var temp = new byte[cipherText.Length - MAC_BYTES];
                //        Array.Copy(cipherText, MAC_BYTES, temp, 0, cipherText.Length - MAC_BYTES);

                //        cipherText = temp;
                //    }
                //}
            }

            var buffer = new byte[cipherText.Length - MAC_BYTES];
            var ret = SodiumLibrary.crypto_secretbox_xchacha20poly1305_open_easy(buffer, cipherText, cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to open SecretBox");

            return buffer;
        }


        /// <summary>Opens a detached Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="cipherText">Hex-encoded string to be opened</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305OpenDetached(string cipherText, byte[] mac, byte[] nonce, byte[] key) =>
            Xchacha20Poly1305OpenDetached(Utilities.HexToBinary(cipherText), mac, nonce, key);

        /// <summary>Opens a detached Secret Box using XChaCha20 and Poly1305 algorithms.</summary>
        /// <param name="detached">A detached object.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305OpenDetached(DetachedBox detached, byte[] nonce, byte[] key) =>
            Xchacha20Poly1305OpenDetached(detached.CipherText, detached.Mac, nonce, key);

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Xchacha20Poly1305OpenDetached(byte[] cipherText, byte[] mac, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length,
                    $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), (nonce == null) ? 0 : nonce.Length,
                    $"nonce must be {NONCE_BYTES} bytes in length.");

            //validate the length of the mac
            if (mac == null || mac.Length != MAC_BYTES)
                throw new MacOutOfRangeException(nameof(mac), (mac == null) ? 0 : mac.Length,
                    $"mac must be {MAC_BYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];
            var ret = SodiumLibrary.crypto_secretbox_xchacha20poly1305_open_detached(buffer, cipherText, mac, cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to open detached SecretBox");

            return buffer;
        }

    }
}
