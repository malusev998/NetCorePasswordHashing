using System;
using System.Security.Cryptography;
using System.Text;
using PasswordHash.Contracts;

namespace PasswordHash
{
    public abstract class Hasher : IHasher
    {
        protected readonly RNGCryptoServiceProvider _randomCryptoServiceProvider;

        public Hasher()
            : this(10, 32, new RNGCryptoServiceProvider())
        {
        }

        public Hasher(Int32 saltSize)
            : this(10, saltSize, new RNGCryptoServiceProvider())
        {
        }

        public Hasher(Int32 cost, Int32 saltSize)
            : this(cost, saltSize, new RNGCryptoServiceProvider())
        {
        }


        public Hasher(Int32 cost, Int32 saltSize, RNGCryptoServiceProvider provider)
        {
            Iterations = (Int32) Math.Pow(2, cost);
            SaltSize = saltSize;
            _randomCryptoServiceProvider = provider;
        }

        public Int32 HashSize { get; } = 128;
        public Int32 Iterations { get; }
        public Int32 SaltSize { get; }

        public String Hash(String password)
        {
            return Hash(Encoding.UTF8.GetBytes(password));
        }

        public bool Verify(String password, String hash)
        {
            return Verify(Encoding.UTF8.GetBytes(password), Convert.FromBase64String(hash));
        }

        public Boolean Verify(String password, Byte[] hash)
        {
            return Verify(Encoding.UTF8.GetBytes(password), hash);
        }

        public Boolean Verify(Byte[] password, String hash)
        {
            return Verify(password, Convert.FromBase64String(hash));
        }


        public abstract Boolean Verify(Byte[] password, Byte[] hash);

        public abstract String Hash(Byte[] password);
    }
}