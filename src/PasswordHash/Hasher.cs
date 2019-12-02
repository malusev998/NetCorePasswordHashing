using System;
using System.Security.Cryptography;
using System.Text;
using PasswordHash.Contracts;

namespace PasswordHash
{
    public abstract class Hasher : IHasher
    {
        protected readonly RNGCryptoServiceProvider RandomCryptoServiceProvider;

        public Hasher()
            : this(10, 32, new RNGCryptoServiceProvider())
        {
        }

        public Hasher(int saltSize)
            : this(10, saltSize, new RNGCryptoServiceProvider())
        {
        }

        public Hasher(int cost, int saltSize)
            : this(cost, saltSize, new RNGCryptoServiceProvider())
        {
        }


        public Hasher(int cost, int saltSize, RNGCryptoServiceProvider provider)
        {
            Iterations = (int) Math.Pow(2, cost);
            SaltSize = saltSize;
            RandomCryptoServiceProvider = provider;
        }

        public int HashSize { get; } = 128;
        public int Iterations { get; }
        public int SaltSize { get; }

        public string Hash(string password)
        {
            return Hash(Encoding.UTF8.GetBytes(password));
        }

        public bool Verify(string password, string hash)
        {
            return Verify(Encoding.UTF8.GetBytes(password), Convert.FromBase64String(hash));
        }

        public bool Verify(string password, byte[] hash)
        {
            return Verify(Encoding.UTF8.GetBytes(password), hash);
        }

        public bool Verify(byte[] password, string hash)
        {
            return Verify(password, Convert.FromBase64String(hash));
        }


        public abstract bool Verify(byte[] password, byte[] hash);

        public abstract string Hash(byte[] password);
    }
}