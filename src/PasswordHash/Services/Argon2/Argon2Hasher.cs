using System;
using System.Runtime.InteropServices;
using PasswordHash.Contracts;

namespace PasswordHash.Services.Argon2
{
    public class Argon2Hasher : IHasher
    {
        public Argon2Hasher(uint timeCost, uint memoryCost, uint threads)
        {
            TimeCost = timeCost;
            MemoryCost = memoryCost;
            Threads = threads;
        }

        public uint TimeCost { get; protected set; }
        public uint MemoryCost { get; protected set; }
        
        public uint Threads { get; protected set; }
        
        [DllImport("libargon2", EntryPoint = "argon2_hash", CallingConvention = CallingConvention.StdCall)]
        private static extern int argon2_hash(
            uint timeCost,
            uint memoryCost,
            uint threads,
            byte[] password,
            ulong passwordLength,
            byte[] salt,
            ulong saltLength,
            byte[] hash,
            ulong hashLength,
            byte[] encoded,
            ulong encodedLength,
            int type,
            uint version
        );
        
        [DllImport("libargon2", EntryPoint = "argon2_verify", CallingConvention = CallingConvention.StdCall)]
        private static extern int argon2_verify(
            byte[] encoded,
            byte[] password,
            ulong passwordLength,
            int type
        );

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