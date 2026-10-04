using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;

namespace Rbac.Api.Authorization;

/// <summary>
/// Server-side permission resolution: instead of stuffing every permission into the JWT, the
/// <see cref="PermissionClaimsTransformation"/> adds the permission claims to the principal right
/// before authorization runs. The authorization code is identical in both modes because it only
/// ever looks at <see cref="CustomClaimTypes.Permission"/> claims.
/// </summary>
public sealed class PermissionClaimsTransformation(
    IPermissionService permissionService,
    HybridCache permissionCache,
    IOptions<PermissionResolutionOptions> options,
    ILogger<PermissionClaimsTransformation> logger) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        // In Token mode the permissions already travelled with the token and this class does nothing.
        if (options.Value.Source is PermissionSource.Token)
        {
            return principal;
        }

        if (principal.Identity?.IsAuthenticated is not true || principal.Identity is not ClaimsIdentity identity)
        {
            return principal;
        }

        // The transformation can run more than once per request (every AuthenticateAsync call).
        // Adding the claims twice would corrupt the principal, so bail out when they are present.
        if (identity.HasClaim(claim => claim.Type == CustomClaimTypes.Permission))
        {
            return principal;
        }

        string? userId = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (string.IsNullOrEmpty(userId))
        {
            logger.LogWarning("Authenticated principal has no 'sub' claim, skipping permission resolution.");
            return principal;
        }

        string[] permissions = await ResolvePermissionsAsync(userId);

        foreach (string permission in permissions)
        {
            identity.AddClaim(new Claim(CustomClaimTypes.Permission, permission));
        }

        logger.LogDebug(
            "Resolved {Count} permission(s) server-side for user {UserId}: {Permissions}",
            permissions.Length,
            userId,
            string.Join(", ", permissions));

        return principal;
    }

    private async Task<string[]> ResolvePermissionsAsync(string userId)
    {
        PermissionResolutionOptions resolutionOptions = options.Value;

        if (resolutionOptions.DisableCache)
        {
            return await permissionService.GetPermissionsAsync(userId);
        }

        // HybridCache de-duplicates concurrent misses (stampede protection) so a burst of requests
        // for a user with no cached permissions produces a single database round trip.
        return await permissionCache.GetOrCreateAsync(
            PermissionCacheKeys.ForUser(userId),
            async token => await permissionService.GetPermissionsAsync(userId, token),
            new HybridCacheEntryOptions { Expiration = resolutionOptions.PermissionCacheDuration });
    }
}

public static class PermissionCacheKeys
{
    private const string Prefix = "rbac:permissions:";

    public static string ForUser(string userId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        return Prefix + userId;
    }
}
