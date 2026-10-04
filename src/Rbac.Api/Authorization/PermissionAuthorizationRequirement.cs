using Microsoft.AspNetCore.Authorization;

namespace Rbac.Api.Authorization;

/// <summary>
/// A single authorization requirement that doubles as its own handler.
/// <para>
/// Combining both in one type keeps the permission check in one readable place: the requirement
/// carries the permissions that are needed, the handler answers the question "does this user have one
/// of them?". Authorization is an OR check by default; use <see cref="PermissionMatchMode.All"/> (or
/// <see cref="PermissionPolicyExtensions.RequireAllPermissions"/>) when every permission is needed.
/// </para>
/// <para>
/// A fresh instance is created for every policy, so it is deliberately not registered in DI. The
/// framework evaluates it because a policy runs the requirements that implement
/// <see cref="IAuthorizationHandler"/>.
/// </para>
/// </summary>
public sealed class PermissionAuthorizationRequirement : AuthorizationHandler<PermissionAuthorizationRequirement>, IAuthorizationRequirement
{
    private readonly ILogger<PermissionAuthorizationRequirement>? _logger;

    /// <summary>Requires at least one of the permissions (OR).</summary>
    public PermissionAuthorizationRequirement(params string[] allowedPermissions)
        : this(PermissionMatchMode.Any, allowedPermissions)
    {
    }

    /// <summary>Requires the permissions to be combined with the given mode.</summary>
    public PermissionAuthorizationRequirement(PermissionMatchMode mode, params string[] allowedPermissions)
        : this(mode, allowedPermissions, logger: null)
    {
    }

    /// <summary>Same as above, with a logger used to explain why a check passed or failed.</summary>
    public PermissionAuthorizationRequirement(
        PermissionMatchMode mode,
        string[] allowedPermissions,
        ILogger<PermissionAuthorizationRequirement>? logger)
    {
        AllowedPermissions = Normalize(allowedPermissions);

        Mode = mode;
        _logger = logger;
    }

    public PermissionMatchMode Mode { get; }

    public IReadOnlyList<string> AllowedPermissions { get; }

    public bool RequiresAllPermissions => Mode is PermissionMatchMode.All;

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionAuthorizationRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);

        // One pass over the claims instead of FindFirst per candidate permission.
        string[] granted = [.. context.User.FindAll(CustomClaimTypes.Permission).Select(claim => claim.Value)];
        HashSet<string> grantedPermissions = new(granted, StringComparer.Ordinal);

        string[] matching = [.. requirement.AllowedPermissions.Where(grantedPermissions.Contains)];

        bool satisfied = requirement.RequiresAllPermissions
            ? matching.Length == requirement.AllowedPermissions.Count
            : matching.Length > 0;

        if (satisfied)
        {
            // Succeeding the requirement is all it takes for the policy to pass.
            context.Succeed(requirement);

            _logger?.LogDebug(
                "Permission check passed for {User} ({Mode}): {Matching}",
                context.User.Identity?.Name ?? "unknown",
                requirement.Mode,
                string.Join(", ", matching));
        }
        else
        {
            // No Succeed call, so the policy fails and the caller gets 403 Forbidden.
            _logger?.LogDebug(
                "Permission check failed for {User} ({Mode}). Required: {Required}. Granted: {Granted}",
                context.User.Identity?.Name ?? "unknown",
                requirement.Mode,
                string.Join(", ", requirement.AllowedPermissions),
                granted.Length == 0 ? "<none>" : string.Join(", ", granted));
        }

        return Task.CompletedTask;
    }

    private static string[] Normalize(string[] allowedPermissions)
    {
        if (allowedPermissions is null || allowedPermissions.Length == 0)
        {
            throw new ArgumentException(
                "At least one permission must be provided.",
                nameof(allowedPermissions));
        }

        string[] normalized =
        [
            .. allowedPermissions
                .Where(permission => !string.IsNullOrWhiteSpace(permission))
                .Select(permission => permission.Trim())
                .Distinct(StringComparer.Ordinal)
        ];

        if (normalized.Length == 0)
        {
            throw new ArgumentException(
                "At least one non-empty permission must be provided.",
                nameof(allowedPermissions));
        }

        return normalized;
    }
}
