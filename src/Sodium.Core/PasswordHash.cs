using Sodium.Exceptions;
using System;
using System.Text;

namespace Sodium
{
    /// <summary>Hashes passwords using the argon2i and scrypt algorithm</summary>
    public class PasswordHash
    {
        private const uint ARGON_STRBYTES = 128U;
        private const uint ARGON_SALTBYTES = 16U;

        private const long ARGON_OPSLIMIT_INTERACTIVE = 4;
        private const long ARGON_OPSLIMIT_MODERATE = 6;
        private const long ARGON_OPSLIMIT_SENSITIVE = 8;

        private const int ARGON_MEMLIMIT_INTERACTIVE = 33554432;
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
                throw new ArgumentNullException("password", "Password cannot be null");

            if (salt == null)
                throw new ArgumentNullException("salt", "Salt cannot be null");

            if (salt.Length != ARGON_SALTBYTES)
                throw new SaltOutOfRangeException(string.Format("Salt must be {0} bytes in length.", ARGON_SALTBYTES));

            if (opsLimit < 3)
                throw new ArgumentOutOfRangeException("opsLimit", "opsLimit the number of passes, has to be at least 3");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException("memLimit", "memLimit cannot be zero or negative");

            if (outputLength <= 0)
                throw new ArgumentOutOfRangeException("outputLength", "OutputLength cannot be zero or negative");

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
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case StrengthArgon.Interactive:
                    opsLimit = ARGON_OPSLIMIT_INTERACTIVE;
                    memLimit = ARGON_MEMLIMIT_INTERACTIVE;
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
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case StrengthArgon.Interactive:
                    opsLimit = ARGON_OPSLIMIT_INTERACTIVE;
                    memLimit = ARGON_MEMLIMIT_INTERACTIVE;
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
                throw new ArgumentNullException("password", "Password cannot be null");

            if (opsLimit < 3)
                throw new ArgumentOutOfRangeException("opsLimit", "opsLimit the number of passes, has to be at least 3");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException("memLimit", "memLimit cannot be zero or negative");

            var buffer = new byte[ARGON_STRBYTES];
            var pass = Encoding.UTF8.GetBytes(password);

            SodiumCore.Init();
            var ret = SodiumLibrary.crypto_pwhash_str(buffer, pass, pass.Length, opsLimit, memLimit);

            if (ret != 0)
            {
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");
            }

            return Encoding.UTF8.GetString(buffer);
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
                throw new ArgumentNullException("password", "Password cannot be null");
            if (hash == null)
                throw new ArgumentNullException("hash", "Hash cannot be null");

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
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case Strength.Interactive:
                    opsLimit = SCRYPT_OPSLIMIT_INTERACTIVE;
                    memLimit = SCRYPT_MEMLIMIT_INTERACTIVE;
                    break;
#pragma warning disable 618
                case Strength.Moderate:
#pragma warning restore 618
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
                throw new ArgumentNullException("password", "Password cannot be null");

            if (opsLimit <= 0)
                throw new ArgumentOutOfRangeException("opsLimit", "opsLimit cannot be zero or negative");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException("memLimit", "memLimit cannot be zero or negative");

            var buffer = new byte[SCRYPT_SALSA208_SHA256_STRBYTES];
            var pass = Encoding.UTF8.GetBytes(password);

            SodiumCore.Init();
            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str(buffer, pass, pass.Length, opsLimit, memLimit);

            if (ret != 0)
            {
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");
            }

            return Encoding.UTF8.GetString(buffer);
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
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case Strength.Interactive:
                    opsLimit = SCRYPT_OPSLIMIT_INTERACTIVE;
                    memLimit = SCRYPT_MEMLIMIT_INTERACTIVE;
                    break;
#pragma warning disable 618
                case Strength.Moderate:
#pragma warning restore 618
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
                throw new ArgumentNullException("password", "Password cannot be null");

            if (salt == null)
                throw new ArgumentNullException("salt", "Salt cannot be null");

            if (salt.Length != SCRYPT_SALSA208_SHA256_SALTBYTES)
                throw new SaltOutOfRangeException(string.Format("Salt must be {0} bytes in length.", SCRYPT_SALSA208_SHA256_SALTBYTES));

            if (opsLimit <= 0)
                throw new ArgumentOutOfRangeException("opsLimit", "opsLimit cannot be zero or negative");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException("memLimit", "memLimit cannot be zero or negative");

            if (outputLength < 16)
                throw new ArgumentOutOfRangeException("outputLength", "OutputLength cannot be less than 16 bytes");

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
                throw new ArgumentNullException("password", "Password cannot be null");
            if (hash == null)
                throw new ArgumentNullException("hash", "Hash cannot be null");

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, password, password.Length);

            return ret == 0;
        }
    }
}
