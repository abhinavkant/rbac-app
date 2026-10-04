namespace Rbac.Api.Authorization;

/// <summary>
/// Where the permission claims that authorization reads come from.
/// Bound from the "Authorization" configuration section.
/// </summary>
public sealed class PermissionResolutionOptions
{
    public const string SectionName = "Authorization";

    /// <summary>
    /// <see cref="PermissionSource.Token"/>: permissions are resolved at login and written into the
    /// JWT. Simple and fast, but a permission change only shows up after the user gets a new token.
    /// <para>
    /// <see cref="PermissionSource.Server"/>: the JWT only carries roles and permissions are resolved
    /// per request from the database (through <see cref="PermissionClaimsTransformation"/>) and cached.
    /// Small tokens, and permission changes take effect within the cache duration.
    /// </para>
    /// </summary>
    public PermissionSource Source { get; set; } = PermissionSource.Token;

    /// <summary>How long resolved permissions are cached in <c>Server</c> mode.</summary>
    public TimeSpan PermissionCacheDuration { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Skip the cache and always hit the database (handy while demoing).</summary>
    public bool DisableCache { get; set; }
}

public enum PermissionSource
{
    /// <summary>Permissions are embedded in the access token.</summary>
    Token = 0,

    /// <summary>Permissions are resolved server-side per request and cached.</summary>
    Server = 1
}
