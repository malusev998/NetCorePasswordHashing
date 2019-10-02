using PasswordHash.Contracts;
using System;
using System.Text;

namespace PasswordHash.Services
{
    public class BCryptHasher : IHasher
    {
        public Int32 Cost { get; }

        public BCryptHasher()
            : this(16)
        {
        }

        public BCryptHasher(Int32 cost)
        {
            Cost = cost;
        }

        public String Hash(String password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, Cost);
        }

        public String Hash(Byte[] password)
        {
            return Hash(Encoding.UTF8.GetString(password));
        }

        public Boolean Verify(String password, String hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public Boolean Verify(String password, Byte[] hash)
        {
            return Verify(password, Encoding.UTF8.GetString(hash));
        }

        public Boolean Verify(Byte[] password, Byte[] hash)
        {
            return Verify(Encoding.UTF8.GetString(password), Encoding.UTF8.GetString(hash));
        }

        public Boolean Verify(Byte[] password, String hash)
        {
            return Verify(Encoding.UTF8.GetString(password), hash);
        }
    }
}
