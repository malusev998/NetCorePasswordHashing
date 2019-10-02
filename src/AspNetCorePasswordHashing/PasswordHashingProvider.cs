using Microsoft.Extensions.DependencyInjection;
using PasswordHash.Contracts;
using PasswordHash.Services;
using System;

namespace PasswordHash
{
    public static class PasswordHashingProvider
    {
        public static IServiceCollection AddPasswordHashingService(this IServiceCollection collection,
            Func<IServiceProvider, IHasher> implementation = null)
        {
            if (implementation == null) implementation = provider => new Rfc2898Hasher();

            return collection.AddSingleton(implementation);
        }

        public static IServiceCollection AddPasswordHashingService<THash>(this IServiceCollection services)
            where THash : class, IHasher, new()
        {
            return services.AddSingleton<IHasher, THash>();
        }
    }
}
