using System;
using System.Security.Cryptography;

namespace PasswordHash.Services
{
    public class Rfc2898Hasher : Hasher
    {
        public override string Hash(byte[] password)
        {
            byte[] salt = new byte[SaltSize];
            RandomCryptoServiceProvider.GetNonZeroBytes(salt);

            using var hasher = new Rfc2898DeriveBytes(password, salt, Iterations);
            byte[] hashPassword = hasher.GetBytes(HashSize);

            const byte separator = (byte)'$';

            byte[] iterations = BitConverter.GetBytes(Iterations);

            // Size of salt + size of hash it self + size of iterations + 2 separator bytes
            byte[] bytes = new byte[HashSize + SaltSize + iterations.Length + 2];
            var offset = 0;

            // First copy the salt into array
            Buffer.BlockCopy(salt, 0, bytes, offset, SaltSize);
            offset += SaltSize;
            // Add separator
            bytes[offset++] = separator;

            // Copy the number of iterations
            Buffer.BlockCopy(iterations, 0, bytes, offset, iterations.Length);
            offset += iterations.Length;
            // Add another separator
            bytes[offset++] = separator;

            // Copy the hashed password
            Buffer.BlockCopy(hashPassword, 0, bytes, offset, HashSize);

            return Convert.ToBase64String(bytes);
        }

        public override bool Verify(byte[] password, byte[] hash)
        {
            return VerifyPassword(password, hash) == 0;
        }

        public int VerifyPassword(byte[] password, byte[] hash)
        {
            byte[] salt = new byte[SaltSize];
            int offset = 0;

            // Copy salt into Buffer
            Buffer.BlockCopy(hash, offset, salt, 0, SaltSize);

            // Move SaltSize + 1 to escape the separator
            offset += SaltSize + 1;

            // Get number of iterations -> 
            int numberOfIterations = BitConverter.ToInt32(hash, offset);

            // Move 5 bytes to the actual password
            offset += 5;

            // Hash the password from the input
            using var hasher = new Rfc2898DeriveBytes(password, salt, numberOfIterations);
            byte[] newHashedPassword = hasher.GetBytes(HashSize);


            int result = 0;

            for (int i = 0; i < HashSize; i++)
                result |= newHashedPassword[i] ^ hash[i + offset];

            return (1 & ((result - 1) >> 8)) - 1;
        }
    }
}