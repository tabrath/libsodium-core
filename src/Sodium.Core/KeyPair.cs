/* Unmerged change from project 'Sodium.Core (netstandard1.6)'
Before:
using System;
After:
using Sodium.Exceptions;

using System;
*/

/* Unmerged change from project 'Sodium.Core (netstandard2.0)'
Before:
using System;
After:
using Sodium.Exceptions;

using System;
*/

/* Unmerged change from project 'Sodium.Core (Xamarin.iOS10)'
Before:
using System;
After:
using Sodium.Exceptions;

using System;
*/
using System;

using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>A public / private key pair.</summary>
    public class KeyPair : IDisposable
    {
        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;

        /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            //verify that the private key length is a multiple of 16
            if (privateKey.Length % 16 != 0)
                throw new KeyOutOfRangeException("Private Key length must be a multiple of 16 bytes.");

            _publicKey = publicKey;

            _privateKey = privateKey;
            _ProtectKey();
        }

        ~KeyPair()
        {
            Dispose();
        }

        /// <summary>Gets or sets the Public Key.</summary>
        public byte[] PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>Gets or sets the Private Key.</summary>
        public byte[] PrivateKey
        {
            get
            {
                _UnprotectKey();
                var tmp = new byte[_privateKey.Length];
                Array.Copy(_privateKey, tmp, tmp.Length);
                _ProtectKey();

                return tmp;
            }
        }

        /// <summary>Dispose of private key in memory.</summary>
        public void Dispose()
        {
            if (_privateKey != null && _privateKey.Length > 0)
                Array.Clear(_privateKey, 0, _privateKey.Length);
        }

        private void _ProtectKey()
        {
#if NET461
            ProtectedMemory.Protect(_privateKey, MemoryProtectionScope.SameProcess);
#endif
        }

        private void _UnprotectKey()
        {
#if NET461
            ProtectedMemory.Unprotect(_privateKey, MemoryProtectionScope.SameProcess);
#endif
        }
    }
}
