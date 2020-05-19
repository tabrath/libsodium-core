using System;
using System.Text;

using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Hashes passwords using the argon2i and scrypt algorithm</summary>
    public class PasswordHash
    {
        private const uint ARGON_STRBYTES = 128U;
        private const uint ARGON_SALTBYTES = 16U;

        private const long ARGON_OPSLIMIT_INTERACTIVE = 4;
        private const long ARGON_OPSLIMIT_MEDIUM = 4;
        private const long ARGON_OPSLIMIT_MODERATE = 6;
        private const long ARGON_OPSLIMIT_SENSITIVE = 8;

        private const int ARGON_MEMLIMIT_INTERACTIVE = 33554432;
        private const int ARGON_MEMLIMIT_MEDIUM = 67108864;
        private const int ARGON_MEMLIMIT_MODERATE = 134217728;
        private const int ARGON_MEMLIMIT_SENSITIVE = 536870912;

        private const uint SCRYPT_SALSA208_SHA256_STRBYTES = 102U;
        private const uint SCRYPT_SALSA208_SHA256_SALTBYTES = 32U;

        private const long SCRYPT_OPSLIMIT_INTERACTIVE = 524288;
        private const long SCRYPT_OPSLIMIT_MODERATE = 8388608;
        private const long SCRYPT_OPSLIMIT_MEDIUM = 8388608;
        private const long SCRYPT_OPSLIMIT_SENSITIVE = 33554432;

        private const int SCRYPT_MEMLIMIT_INTERACTIVE = 16777216;
        private const int SCRYPT_MEMLIMIT_MODERATE = 100000000;
        private const int SCRYPT_MEMLIMIT_MEDIUM = 134217728;
        private const int SCRYPT_MEMLIMIT_SENSITIVE = 1073741824;

        /// <summary>Represents available Argon algorithms</summary>
        public enum ArgonAlgorithm
        {
            /// <summary>2I13, default Argon algorithm</summary>
            Argon_2I13 = 1,
            /// <summary>2ID13 Argon algorithm</summary>
            Argon_2ID13 = 2
        }

        /// <summary>Represents predefined and useful limits for ArgonHashBinary() and ArgonHashString().</summary>
        public enum StrengthArgon
        {
            /// <summary>For interactive sessions (fast: uses 32MB of RAM).</summary>
            Interactive,
            /// <summary>For medium use (medium: uses 64MB of RAM)</summary>
            Medium,
            /// <summary>For normal use (moderate: uses 128MB of RAM).</summary>
            Moderate,
            /// <summary>For highly sensitive data (slow: uses 512MB of RAM).</summary>
            Sensitive
        }

        /// <summary>Represents predefined and useful limits for ScryptHashBinary() and ScryptHashString().</summary>
        public enum Strength
        {
            /// <summary>For interactive sessions (fast: uses 16MB of RAM).</summary>
            Interactive,
            /// <summary>For normal use (moderate: uses 100MB of RAM).</summary>
            [Obsolete("Use Strength.Medium instead.")]
            Moderate,
            /// <summary>For normal use (moderate: uses 128MB of RAM).</summary>
            Medium,
            /// <summary>For more sensitive use (moderate: uses 128MB of RAM).</summary>
            MediumSlow,
            /// <summary>For highly sensitive data (slow: uses more than 1GB of RAM).</summary>
            Sensitive
        }

        public enum HashType
        {
            /// <summary></summary>
            Argon,
            /// <summary></summary>
            Scrypt
        }

        /// <summary>Generates a random byte salt.</summary>
        /// <param name="hashType"></param>
        /// <returns>Returns a byte array with 16 or 32 random bytes</returns>
        [Obsolete("Use ScryptGenerateSalt() or ArgonGenerateSalt() instead.")]
        public static byte[] GenerateSalt(HashType hashType = HashType.Scrypt)
        {
            //Note: the default hash type is Scrypt for now: to keep backward compatibility
            return hashType == HashType.Argon ? ArgonGenerateSalt() : ScryptGenerateSalt();
        }

        /// <summary>Generates a random 32 byte salt for the Scrypt algorithm.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] ScryptGenerateSalt()
        {
            return SodiumCore.GetRandomBytes((int)SCRYPT_SALSA208_SHA256_SALTBYTES);
        }

        /// <summary>Generates a random 16 byte salt for the Argon2i algorithm.</summary>
        /// <returns>Returns a byte array with 16 random bytes</returns>
        public static byte[] ArgonGenerateSalt()
        {
            return SodiumCore.GetRandomBytes((int)ARGON_SALTBYTES);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <param name="alg">Argon Algorithm</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(byte[] password, byte[] salt, long opsLimit, int memLimit, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt cannot be null");

            if (salt.Length != ARGON_SALTBYTES)
                throw new SaltOutOfRangeException($"Salt must be {ARGON_SALTBYTES} bytes in length.");

            if (opsLimit < 3)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit the number of passes, has to be at least 3");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            if (outputLength <= 0)
                throw new ArgumentOutOfRangeException(nameof(outputLength), "OutputLength cannot be zero or negative");

            var buffer = new byte[outputLength];

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash(buffer, buffer.Length, password, password.Length, salt, opsLimit, memLimit, (int)alg);

            if (ret != 0)
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");

            return buffer;
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <param name="alg">Argon Algorithm</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(string password, string salt, StrengthArgon limit = StrengthArgon.Interactive, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            return ArgonHashBinary(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), limit, outputLength, alg);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <param name="alg">Argon Algorithm</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(byte[] password, byte[] salt, StrengthArgon limit = StrengthArgon.Interactive, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            var (opsLimit, memLimit) = GetArgonOpsAndMemoryLimit(limit);

            return ArgonHashBinary(password, salt, opsLimit, memLimit, outputLength, alg);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(string password, string salt, long opsLimit, int memLimit, long outputLength = ARGON_SALTBYTES)
        {
            var pass = Encoding.UTF8.GetBytes(password);
            var saltAsBytes = Encoding.UTF8.GetBytes(salt);

            return ArgonHashBinary(pass, saltAsBytes, opsLimit, memLimit, outputLength);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ArgonHashString(string password, StrengthArgon limit = StrengthArgon.Interactive)
        {
            var (opsLimit, memLimit) = GetArgonOpsAndMemoryLimit(limit);

            return ArgonHashString(password, opsLimit, memLimit);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ArgonHashString(string password, long opsLimit, int memLimit)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (opsLimit < 3)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit the number of passes, has to be at least 3");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            var buffer = new byte[ARGON_STRBYTES];
            var pass = Encoding.UTF8.GetBytes(password);

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_str(buffer, pass, pass.Length, opsLimit, memLimit);

            if (ret != 0)
            {
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");
            }

            return Utilities.UnsafeAsciiBytesToString(buffer);
        }

        /// <summary>Verifies that a hash generated with ArgonHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ArgonHashStringVerify(string hash, string password)
        {
            return ArgonHashStringVerify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
        }

        /// <summary>Verifies that a hash generated with ArgonHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ArgonHashStringVerify(byte[] hash, byte[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");
            if (hash == null)
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_str_verify(hash, password, password.Length);

            return ret == 0;
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ScryptHashString(string password, Strength limit = Strength.Interactive)
        {
            var (opsLimit, memLimit) = GetScryptOpsAndMemoryLimit(limit);

            return ScryptHashString(password, opsLimit, memLimit);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ScryptHashString(string password, long opsLimit, int memLimit)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (opsLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit cannot be zero or negative");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            var buffer = new byte[SCRYPT_SALSA208_SHA256_STRBYTES];
            var pass = Encoding.UTF8.GetBytes(password);

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str(buffer, pass, pass.Length, opsLimit, memLimit);

            if (ret != 0)
            {
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");
            }

            return Utilities.UnsafeAsciiBytesToString(buffer);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(string password, string salt, Strength limit = Strength.Interactive, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            return ScryptHashBinary(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), limit, outputLength);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(byte[] password, byte[] salt, Strength limit = Strength.Interactive, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            var (opsLimit, memLimit) = GetScryptOpsAndMemoryLimit(limit);

            return ScryptHashBinary(password, salt, opsLimit, memLimit, outputLength);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(string password, string salt, long opsLimit, int memLimit, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            var pass = Encoding.UTF8.GetBytes(password);
            var saltAsBytes = Encoding.UTF8.GetBytes(salt);

            return ScryptHashBinary(pass, saltAsBytes, opsLimit, memLimit, outputLength);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(byte[] password, byte[] salt, long opsLimit, int memLimit, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt cannot be null");

            if (salt.Length != SCRYPT_SALSA208_SHA256_SALTBYTES)
                throw new SaltOutOfRangeException($"Salt must be {SCRYPT_SALSA208_SHA256_SALTBYTES} bytes in length.");

            if (opsLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit cannot be zero or negative");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            if (outputLength < 16)
                throw new ArgumentOutOfRangeException(nameof(outputLength), "OutputLength cannot be less than 16 bytes");

            var buffer = new byte[outputLength];

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256(buffer, buffer.Length, password, password.Length, salt, opsLimit, memLimit);

            if (ret != 0)
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");

            return buffer;
        }

        /// <summary>Verifies that a hash generated with ScryptHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ScryptHashStringVerify(string hash, string password)
        {
            return ScryptHashStringVerify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
        }

        /// <summary>Verifies that a hash generated with ScryptHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ScryptHashStringVerify(byte[] hash, byte[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");
            if (hash == null)
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, password, password.Length);

            return ret == 0;
        }

        /// <summary>
        /// Checks if the current password hash needs rehashing
        /// </summary>
        /// <param name="password">Password that needs rehashing</param>
        /// <param name="opsLimit"></param>
        /// <param name="memLimit"></param>
        /// <returns></returns>
        public static bool ArgonPasswordNeedsRehash(byte[] password, long opsLimit, int memLimit)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password", "Password cannot be null");
            }

            SodiumCore.Init();

            int status = SodiumLibrary.crypto_pwhash_str_needs_rehash(password, opsLimit, memLimit);

            if (status == -1)
            {
                throw new InvalidArgonPasswordString();
            }

            return status == 1;
        }


        public static bool ArgonPasswordNeedsRehash(byte[] password, StrengthArgon limit = StrengthArgon.Interactive)
        {
            var (opsLimit, memLimit) = GetArgonOpsAndMemoryLimit(limit);

            return ArgonPasswordNeedsRehash(password, opsLimit, memLimit);
        }

        public static bool ArgonPasswordNeedsRehash(string password, StrengthArgon limit = StrengthArgon.Interactive)
        {
            return ArgonPasswordNeedsRehash(Encoding.UTF8.GetBytes(password), limit);
        }

        public static bool ArgonPasswordNeedsRehash(string password, long opsLimit, int memLimit)
        {
            return ArgonPasswordNeedsRehash(Encoding.UTF8.GetBytes(password), opsLimit, memLimit);
        }

        /// <summary>
        /// Checks if the current SCrypt password hash needs rehashing.  Will return false
        /// if the hash values don't match what is expected.
        /// </summary>
        /// <param name="password">Password that needs rehashing</param>
        /// <param name="opsLimit">Expected opsLimit</param>
        /// <param name="memLimit">Expected memLimit</param>
        /// <returns>True if the hash has the expected ops and mem limits, false otherwise.</returns>
        public static bool ScryptPasswordNeedsRehash(byte[] password, long opsLimit, int memLimit)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password", "Password cannot be null");
            }

            SodiumCore.Init();

            int status = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(password, opsLimit, memLimit);

            if (status == -1)
            {
                throw new InvalidSodiumPasswordString();
            }

            return status == 1;
        }

        public static bool ScryptPasswordNeedsRehash(byte[] password, Strength limit = Strength.Interactive)
        {
            var (opsLimit, memLimit) = GetScryptOpsAndMemoryLimit(limit);

            return ScryptPasswordNeedsRehash(password, opsLimit, memLimit);
        }

        public static bool ScryptPasswordNeedsRehash(string password, Strength limit = Strength.Interactive)
        {
            return ScryptPasswordNeedsRehash(Encoding.UTF8.GetBytes(password), limit);
        }

        public static bool ScryptPasswordNeedsRehash(string password, long opsLimit, int memLimit)
        {
            return ScryptPasswordNeedsRehash(Encoding.UTF8.GetBytes(password), opsLimit, memLimit);
        }

        private static (long opsLimit, int memLimit) GetArgonOpsAndMemoryLimit(StrengthArgon limit = StrengthArgon.Interactive)
        {
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case StrengthArgon.Interactive:
                    opsLimit = ARGON_OPSLIMIT_INTERACTIVE;
                    memLimit = ARGON_MEMLIMIT_INTERACTIVE;
                    break;
                case StrengthArgon.Medium:
                    opsLimit = ARGON_OPSLIMIT_MEDIUM;
                    memLimit = ARGON_MEMLIMIT_MEDIUM;
                    break;
                case StrengthArgon.Moderate:
                    opsLimit = ARGON_OPSLIMIT_MODERATE;
                    memLimit = ARGON_MEMLIMIT_MODERATE;
                    break;
                case StrengthArgon.Sensitive:
                    opsLimit = ARGON_OPSLIMIT_SENSITIVE;
                    memLimit = ARGON_MEMLIMIT_SENSITIVE;
                    break;
                default:
                    opsLimit = ARGON_OPSLIMIT_INTERACTIVE;
                    memLimit = ARGON_MEMLIMIT_INTERACTIVE;
                    break;
            }
            return (opsLimit, memLimit);
        }

        private static (long opsLimit, int memLimit) GetScryptOpsAndMemoryLimit(Strength limit = Strength.Interactive)
        {
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case Strength.Interactive:
                    opsLimit = SCRYPT_OPSLIMIT_INTERACTIVE;
                    memLimit = SCRYPT_MEMLIMIT_INTERACTIVE;
                    break;
                case Strength.Moderate:
                    opsLimit = SCRYPT_OPSLIMIT_MODERATE;
                    memLimit = SCRYPT_MEMLIMIT_MODERATE;
                    break;
                case Strength.Medium:
                    opsLimit = SCRYPT_OPSLIMIT_MEDIUM;
                    memLimit = SCRYPT_MEMLIMIT_MEDIUM;
                    break;
                case Strength.MediumSlow:
                    //to slow the process down, use the sensitive ops limit
                    opsLimit = SCRYPT_OPSLIMIT_SENSITIVE;
                    memLimit = SCRYPT_MEMLIMIT_MEDIUM;
                    break;
                case Strength.Sensitive:
                    opsLimit = SCRYPT_OPSLIMIT_SENSITIVE;
                    memLimit = SCRYPT_MEMLIMIT_SENSITIVE;
                    break;
                default:
                    opsLimit = SCRYPT_OPSLIMIT_INTERACTIVE;
                    memLimit = SCRYPT_MEMLIMIT_INTERACTIVE;
                    break;
            }

            return (opsLimit, memLimit);
        }
    }
}
