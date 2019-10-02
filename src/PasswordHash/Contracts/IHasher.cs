namespace PasswordHash.Contracts
{
    public interface IHasher
    {
        string Hash(string password);
        string Hash(byte[] password);

        bool Verify(string password, string hash);
        bool Verify(string password, byte[] hash);
        bool Verify(byte[] password, byte[] hash);
        bool Verify(byte[] password, string hash);
    }
}