namespace Rbac.Api.Authorization;

/// <summary>
/// How multiple permissions on the same policy are combined.
/// </summary>
public enum PermissionMatchMode
{
    /// <summary>OR - the user needs at least one of the permissions (the common case).</summary>
    Any = 0,

    /// <summary>AND - the user needs every listed permission.</summary>
    All = 1
}
