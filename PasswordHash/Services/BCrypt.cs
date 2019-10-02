using System;
using PasswordHash.Contracts;

namespace PasswordHash.Services
{
    public class BCrypt : IHasher
    {
        public string Hash(string password)
        {
            throw new NotImplementedException();
        }

        public string Hash(byte[] password)
        {
            throw new NotImplementedException();
        }

        public bool Verify(string password, string hash)
        {
            throw new NotImplementedException();
        }

        public bool Verify(string password, byte[] hash)
        {
            throw new NotImplementedException();
        }

        public bool Verify(byte[] password, byte[] hash)
        {
            throw new NotImplementedException();
        }

        public bool Verify(byte[] password, string hash)
        {
            throw new NotImplementedException();
        }
    }
}