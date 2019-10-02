using System;
using System.Text;
using PasswordHash.Services;
using Xunit;

namespace PasswordHashTests
{
    public class Rfc2898Test
    {
        [Fact]
        public void GenerateNewSalt()
        {
            var hasher = new Rfc2898Hasher();

            Assert.Equal(1024, hasher.Iterations);
            Assert.Equal(128, hasher.HashSize);
            Assert.Equal(32, hasher.SaltSize);


            var hash = hasher.Hash("password");

            Assert.NotNull(hash);
        }

        [Fact]
        public void ValidatePassword()
        {
            var hasher = new Rfc2898Hasher();
            var hash = hasher.Hash("password");
            var bytes = Convert.FromBase64String(hash);

            Assert.True(hasher.Verify("password", bytes));
        }

        [Fact]
        public void ValidatePasswordAsBytes()
        {
            var hasher = new Rfc2898Hasher();
            var hash = hasher.Hash("password");

            hasher.Verify(Encoding.UTF8.GetBytes("password"), hash);
        }


        [Fact]
        public void ValidatePasswordWithHashString()
        {
            var hasher = new Rfc2898Hasher();
            var hash = hasher.Hash("password");

            hasher.Verify("password", hash);
        }

        [Fact]
        public void ValidateWrongPassword()
        {
            var hasher = new Rfc2898Hasher();
            var hash = hasher.Hash("password");
            var bytes = Convert.FromBase64String(hash);
            Assert.False(hasher.Verify("not good password", bytes));
        }
    }
}