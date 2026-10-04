using Microsoft.AspNetCore.Authorization;

namespace Rbac.Api.Authorization;

/// <summary>
/// Builds the permission policies the controllers authorize against. One call per permission, once, at startup:
/// <code>authorization.AddPolicy(permission, policy => policy.RequirePermission(permission))</code>
/// <para>
/// The same methods also serve Minimal API endpoints, where the permission list does not have to be known at
/// startup: <code>.RequireAuthorization(policy => policy.RequirePermission(Permissions.OrdersCreate))</code>
/// </para>
/// </summary>
public static class PermissionPolicyExtensions
{
    /// <summary>Requires at least one of the permissions (OR).</summary>
    public static AuthorizationPolicyBuilder RequirePermission(
        this AuthorizationPolicyBuilder builder,
        params string[] allowedPermissions)
        => builder.RequirePermission(PermissionMatchMode.Any, allowedPermissions);

    /// <summary>Requires the permissions to be combined using the given mode.</summary>
    public static AuthorizationPolicyBuilder RequirePermission(
        this AuthorizationPolicyBuilder builder,
        PermissionMatchMode mode,
        params string[] allowedPermissions)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddRequirements(new PermissionAuthorizationRequirement(mode, allowedPermissions));

        return builder;
    }

    /// <summary>Requires every permission (AND).</summary>
    public static AuthorizationPolicyBuilder RequireAllPermissions(
        this AuthorizationPolicyBuilder builder,
        params string[] requiredPermissions)
        => builder.RequirePermission(PermissionMatchMode.All, requiredPermissions);
}
