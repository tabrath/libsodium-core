using System;
using System.Runtime.InteropServices;

namespace Sodium
{
    /// <summary>
    /// libsodium library binding.
    /// </summary>
    public static partial class SodiumLibrary
    {

#if IOS
        const string DllName = "__Internal";
#else
        const string DllName = "libsodium";
#endif

        //sodium_init
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_init();

        //randombytes_buf
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf(byte[] buffer, int size);

        //randombytes_uniform
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int randombytes_uniform(int upperBound);

        //sodium_increment
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_increment(byte[] buffer, long length);

        //sodium_compare
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_compare(byte[] a, byte[] b, long length);

        //sodium_version_string
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_version_string();

        //crypto_hash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash(byte[] buffer, byte[] message, long length);

        //crypto_hash_sha512
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512(byte[] buffer, byte[] message, long length);

        //crypto_hash_sha256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256(byte[] buffer, byte[] message, long length);

        //crypto_generichash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength);

        //crypto_generichash_blake2b_salt_personal
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_salt_personal(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength, byte[] salt, byte[] personal);

        //crypto_onetimeauth
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth(byte[] buffer, byte[] message, long messageLength, byte[] key);

        //crypto_onetimeauth_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_verify(byte[] signature, byte[] message, long messageLength, byte[] key);

        //crypto_pwhash_str
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);

        //crypto_pwhash_str_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_verify(byte[] buffer, byte[] password, long passLength);

        //crypto_pwhash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit, int alg);

        //crypto_pwhash_scryptsalsa208sha256_str
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);

        //crypto_pwhash_scryptsalsa208sha256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit);

        //crypto_pwhash_scryptsalsa208sha256_str_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_verify(byte[] buffer, byte[] password, long passLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_needs_rehash(byte[] buffer, long opsLimit, int memLimit);

        //crypto_sign_keypair
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

        //crypto_sign_seed_keypair
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

        //crypto_sign
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);

        //crypto_sign_open
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_open(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);

        //crypto_sign_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_detached(byte[] signature, ref long signatureLength, byte[] message, long messageLength, byte[] key);

        //crypto_sign_verify_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_verify_detached(byte[] signature, byte[] message, long messageLength, byte[] key);

        //crypto_sign_ed25519_sk_to_seed
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(byte[] seed, byte[] secretKey);

        //crypto_sign_ed25519_sk_to_pk
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_pk(byte[] publicKey, byte[] secretKey);

        //crypto_sign_ed25519_pk_to_curve25519
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_pk_to_curve25519(byte[] curve25519Pk, byte[] ed25519Pk);

        //crypto_sign_ed25519_sk_to_curve25519
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_curve25519(byte[] curve25519Sk, byte[] ed25519Sk);

        //crypto_box_keypair
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_keypair(byte[] publicKey, byte[] secretKey);

        //crypto_box_seed_keypair
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

        //crypto_box_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_easy(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

        //crypto_box_open_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_detached(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] pk, byte[] sk);

        //crypto_box_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_easy(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

        //crypto_box_open_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_detached(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] pk, byte[] sk);

        //crypto_box_seedbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seedbytes();

        //crypto_scalarmult_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_bytes();

        //crypto_scalarmult_scalarbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_scalarbytes();

        //crypto_scalarmult_primitive
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern byte crypto_scalarmult_primitive();

        //crypto_scalarmult_base
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_base(byte[] q, byte[] n);

        //crypto_scalarmult
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult(byte[] q, byte[] n, byte[] p);

        //crypto_box_seal
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal(byte[] buffer, byte[] message, long messageLength, byte[] pk);

        //crypto_box_seal_open
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal_open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] pk, byte[] sk);

        //crypto_secretbox_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_easy(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //crypto_secretbox_open_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_easy(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);

        //crypto_secretbox_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_detached(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //crypto_secretbox_open_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_detached(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] key);
        
        //crypto_secretbox_xchacha20poly1305_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_easy(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //crypto_secretbox_xchacha20poly1305_open_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_open_easy(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);

        //crypto_secretbox_xchacha20poly1305_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_detached(byte[] buffer, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //crypto_secretbox_xchacha20poly1305_open_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_open_detached(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] key);

        //crypto_auth
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth(byte[] buffer, byte[] message, long messageLength, byte[] key);

        //crypto_auth_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_verify(byte[] signature, byte[] message, long messageLength, byte[] key);

        //crypto_auth_hmacsha256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256(byte[] buffer, byte[] message, long messageLength, byte[] key);

        //crypto_auth_hmacsha256_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_verify(byte[] signature, byte[] message, long messageLength, byte[] key);

        //crypto_auth_hmacsha512
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512(byte[] signature, byte[] message, long messageLength, byte[] key);

        //crypto_auth_hmacsha512_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_verify(byte[] signature, byte[] message, long messageLength, byte[] key);

        //crypto_shorthash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash(byte[] buffer, byte[] message, long messageLength, byte[] key);

        //crypto_stream_xor
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_xor(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //crypto_stream_chacha20_xor
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_chacha20_xor(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

        //sodium_bin2hex
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2hex(byte[] hex, int hexMaxlen, byte[] bin, int binLen);

        //sodium_hex2bin
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_hex2bin(IntPtr bin, int binMaxlen, string hex, int hexLen, string ignore, out int binLen, string hexEnd);

        //sodium_bin2base64
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2base64(byte[] b64, int b64Maxlen, byte[] bin, int binLen, int variant);

        //sodium_base642bin
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base642bin(IntPtr bin, int binMaxlen, string b64, int b64Len, string ignore, out int binLen, out char b64End, int variant);

        //sodium_base64_encoded_len
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base64_encoded_len(int binLen, int variant);

        //crypto_aead_chacha20poly1305_ietf_encrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_ietf_encrypt(IntPtr cipher, out long cipherLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        //crypto_aead_chacha20poly1305_ietf_decrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_ietf_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] cipher, long cipherLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        //crypto_aead_chacha20poly1305_encrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_encrypt(IntPtr cipher, out long cipherLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        //crypto_aead_chacha20poly1305_decrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] cipher, long cipherLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        //crypto_aead_xchacha20poly1305_ietf_encrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(IntPtr cipher, out long cipherLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        //crypto_aead_xchacha20poly1305_ietf_decrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] cipher, long cipherLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        //crypto_aead_aes256gcm_is_available
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_is_available();

        //crypto_aead_aes256gcm_encrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_encrypt(IntPtr cipher, out long cipherLength, byte[] message, long messageLength, byte[] additionalData, long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);

        //crypto_aead_aes256gcm_decrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_decrypt(IntPtr message, out long messageLength, byte[] nsec, byte[] cipher, long cipherLength, byte[] additionalData, long additionalDataLength, byte[] nonce, byte[] key);

        //crypto_generichash_init
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_init(IntPtr state, byte[] key, int keySize, int hashSize);

        //crypto_generichash_update
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_update(IntPtr state, byte[] message, long messageLength);

        //crypto_generichash_final
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_final(IntPtr state, byte[] buffer, int bufferLength);

        //crypto_generichash_state
        [StructLayout(LayoutKind.Sequential, Size = 384)]
        internal struct HashState
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public ulong[] h;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] t;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] f;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] buf;

            public uint buflen;

            public byte last_node;
        }

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_xchacha20(byte[] buffer, int bufferLength, byte[] nonce, byte[] key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_xchacha20_xor(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
    }
}
