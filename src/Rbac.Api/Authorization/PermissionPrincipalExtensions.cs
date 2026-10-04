using System.Security.Claims;

namespace Rbac.Api.Authorization;

/// <summary>
/// Reading permission claims off a principal. Used by the requirement, by the claims transformation and by the
/// 403 problem document.
/// </summary>
public static class PermissionPrincipalExtensions
{
    /// <summary>Reads the permission claims off a principal.</summary>
    public static IReadOnlyList<string> GetPermissions(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        return [.. principal.FindAll(CustomClaimTypes.Permission).Select(claim => claim.Value)];
    }

    /// <summary>True when the principal carries the permission claim.</summary>
    public static bool HasPermission(this ClaimsPrincipal principal, string permission)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        return principal.HasClaim(CustomClaimTypes.Permission, permission);
    }

    /// <summary>True when the principal carries every permission claim.</summary>
    public static bool HasAllPermissions(this ClaimsPrincipal principal, params string[] permissions)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(permissions);

        return permissions.All(principal.HasPermission);
    }
}
