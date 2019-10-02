using PasswordHash.Services;
using System;
using System.Text;
using Xunit;

namespace PasswordHashTests
{
    public class Rfc2898Test
    {
        [Fact]
        public void GenerateNewSalt()
        {
            Rfc2898Hasher hasher = new Rfc2898Hasher();

            Assert.Equal(1024, hasher.Iterations);
            Assert.Equal(128, hasher.HashSize);
            Assert.Equal(32, hasher.SaltSize);


            String hash = hasher.Hash("password");

            Assert.NotNull(hash);
        }

        [Fact]
        public void ValidatePassword()
        {
            Rfc2898Hasher hasher = new Rfc2898Hasher();
            String hash = hasher.Hash("password");
            Byte[] bytes = Convert.FromBase64String(hash);

            Assert.True(hasher.Verify("password", bytes));
        }

        [Fact]
        public void ValidatePasswordAsBytes()
        {
            Rfc2898Hasher hasher = new Rfc2898Hasher();
            String hash = hasher.Hash("password");

            hasher.Verify(Encoding.UTF8.GetBytes("password"), hash);
        }


        [Fact]
        public void ValidatePasswordWithHashString()
        {
            Rfc2898Hasher hasher = new Rfc2898Hasher();
            String hash = hasher.Hash("password");

            hasher.Verify("password", hash);
        }

        [Fact]
        public void ValidateWrongPassword()
        {
            Rfc2898Hasher hasher = new Rfc2898Hasher();
            String hash = hasher.Hash("password");
            Byte[] bytes = Convert.FromBase64String(hash);
            Assert.False(hasher.Verify("not good password", bytes));
        }
    }
}
