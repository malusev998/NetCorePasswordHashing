using PasswordHash.Contracts;
using System;
using System.Text;

namespace PasswordHash.Services
{
    public class BCryptHasher : IHasher
    {
        public int Cost { get; }

        public BCryptHasher()
            : this(16)
        {
        }

        public BCryptHasher(int cost)
        {
            Cost = cost;
        }

        public string Hash(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, Cost);
        }

        public string Hash(byte[] password)
        {
            return Hash(Encoding.UTF8.GetString(password));
        }

        public bool Verify(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public bool Verify(string password, byte[] hash)
        {
            return Verify(password, Encoding.UTF8.GetString(hash));
        }

        public bool Verify(byte[] password, byte[] hash)
        {
            return Verify(Encoding.UTF8.GetString(password), Encoding.UTF8.GetString(hash));
        }

        public bool Verify(byte[] password, string hash)
        {
            return Verify(Encoding.UTF8.GetString(password), hash);
        }
    }
}
