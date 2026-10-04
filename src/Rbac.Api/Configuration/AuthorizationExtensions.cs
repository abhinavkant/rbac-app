using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Security;

namespace Rbac.Api.Configuration;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddRbacAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<PermissionResolutionOptions>()
            .Configure(options => BindPermissionOptions(configuration, options))
            .Validate(
                options => Enum.IsDefined(options.Source),
                $"{PermissionResolutionOptions.SectionName}:PermissionSource must be 'Token' or 'Server'.")
            .Validate(
                options => options.PermissionCacheDuration > TimeSpan.Zero,
                "Authorization:PermissionCacheDurationInSeconds must be greater than zero.")
            .ValidateOnStart();

        AuthorizationBuilder authorization = services.AddAuthorizationBuilder();

        // One named policy per permission, so an action can name the permission it needs and nothing else:
        //   [Authorize(Policy = Permissions.UsersRead)]
        //
        // RequireAuthenticatedUser() is not optional here. A policy that only carries the permission
        // requirement would answer an anonymous caller with 403 Forbidden, because the default policy (which
        // is what turns "not authenticated" into 401) is replaced by a named policy rather than added to it.
        foreach (string permission in Permissions.All)
        {
            authorization.AddPolicy(
                permission,
                policy => policy.RequireAuthenticatedUser().RequirePermission(permission));
        }

        // The one action that needs two permissions at once.
        authorization.AddPolicy(
            PermissionPolicies.ReportsReadAndExport,
            policy => policy
                .RequireAuthenticatedUser()
                .RequireAllPermissions(Permissions.ReportsRead, Permissions.ReportsExport));

        // No IAuthorizationHandler registration here on purpose: PermissionAuthorizationRequirement is
        // both the requirement and the handler, and a fresh instance is created per policy by
        // RequirePermission(...). Registering it as a singleton would add a second, unconfigured
        // instance that the framework evaluates for every policy in the application.

        services.AddScoped<IAuthorizationCatalog, DatabaseAuthorizationCatalog>();

        // Caches server-side permission lookups. HybridCache also protects against a stampede of
        // concurrent cache misses for the same user.
        services.AddDistributedMemoryCache();
        services.AddHybridCache();

        // Registered in both modes and the mode is read from options at run time: deciding during
        // startup would make the choice depend on when the configuration snapshot is taken.
        services.AddScoped<IClaimsTransformation, PermissionClaimsTransformation>();

        return services;
    }

    private static void BindPermissionOptions(IConfiguration configuration, PermissionResolutionOptions options)
    {
        IConfigurationSection section = configuration.GetSection(PermissionResolutionOptions.SectionName);

        string? configuredSource = section["PermissionSource"];

        if (!string.IsNullOrWhiteSpace(configuredSource))
        {
            // An unparsable value becomes an undefined enum member so the Validate above reports it
            // at startup instead of silently falling back to a default. An absent value keeps the
            // default from PermissionResolutionOptions.
            options.Source = Enum.TryParse(configuredSource, ignoreCase: true, out PermissionSource source)
                ? source
                : (PermissionSource)(-1);
        }

        options.DisableCache = section.GetValue("DisableCache", false);
        options.PermissionCacheDuration = TimeSpan.FromSeconds(section.GetValue("PermissionCacheDurationInSeconds", 60));
    }
}
