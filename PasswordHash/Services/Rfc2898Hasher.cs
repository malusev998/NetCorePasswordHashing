using System;
using System.Security.Cryptography;

namespace PasswordHash.Services
{
    public class Rfc2898Hasher : Hasher
    {
        public override String Hash(Byte[] password)
        {
            Byte[] salt = new Byte[SaltSize];
            _randomCryptoServiceProvider.GetNonZeroBytes(salt);

            using Rfc2898DeriveBytes hasher = new Rfc2898DeriveBytes(password, salt, Iterations);
            Byte[] hashPassword = hasher.GetBytes(HashSize);

            Byte separator = (Byte)'$';

            Byte[] iterations = BitConverter.GetBytes(Iterations);

            // Size of salt + size of hash it self + size of iterations + 2 separator bytes
            Byte[] bytes = new Byte[HashSize + SaltSize + iterations.Length + 2];
            Int32 offset = 0;

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
            Byte[] salt = new byte[SaltSize];
            Int32 offset = 0;

            // Copy salt into Buffer
            Buffer.BlockCopy(hash, offset, salt, 0, SaltSize);

            // Move SaltSize + 1 to escape the separator
            offset += SaltSize + 1;

            // Get number of iterations -> 
            Int32 numberOfIterations = BitConverter.ToInt32(hash, offset);

            // Move 5 bytes to the actual password
            offset += 5;

            // Hash the password from the input
            using Rfc2898DeriveBytes hasher = new Rfc2898DeriveBytes(password, salt, numberOfIterations);
            Byte[] newHashedPassword = hasher.GetBytes(HashSize);

            for (Int32 i = 0; i < HashSize; i++)
                if (newHashedPassword[i] != hash[i + offset])
                    return false;
            return true;
        }
    }
}