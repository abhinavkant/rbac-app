using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Security;

namespace Rbac.Api.Configuration;

public static class DataExtensions
{
    public static IServiceCollection AddRbacData(this IServiceCollection services, IConfiguration configuration)
    {
        // Single-file SQLite keeps the sample self-contained: no server, no migrations to run.
        string connectionString = configuration.GetConnectionString("RbacDb") ?? "Data Source=rbac.db";

        services.AddDbContext<RbacDbContext>(options => options.UseSqlite(connectionString));

        services.AddScoped<RbacSeeder>();
        services.AddScoped<IPermissionService, EfPermissionService>();
        services.AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();
        services.AddSingleton<ITokenService, TokenService>();

        // Creates the database and seeds roles, permissions and users on startup.
        services.AddHostedService<DatabaseInitializer>();

        return services;
    }
}
