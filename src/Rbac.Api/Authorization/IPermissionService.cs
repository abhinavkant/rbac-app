namespace Rbac.Api.Authorization;

/// <summary>
/// Reads the effective permissions of a user: everything granted through roles plus everything
/// granted directly to the user (the "no new role needed" extension point).
/// </summary>
public interface IPermissionService
{
    /// <summary>Distinct, sorted permission names the user currently holds.</summary>
    Task<string[]> GetPermissionsAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Role names assigned to the user.</summary>
    Task<string[]> GetRolesAsync(string userId, CancellationToken cancellationToken = default);
}
