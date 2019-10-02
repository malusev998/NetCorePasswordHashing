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

        public static IServiceCollection AddPBKDF2HashingServie(this IServiceCollection services)
        {
            return services.AddPasswordHashingService<Rfc2898Hasher>();
        }

        public static IServiceCollection AddBCrypyHashingServie(this IServiceCollection services)
        {
            return services.AddPasswordHashingService<BCryptHasher>();
        }
        public static IServiceCollection AddBCrypyHashingServie(this IServiceCollection services, Int32 cost)
        {
            return services.AddPasswordHashingService(_ => new BCryptHasher(cost));
        }
    }
}
