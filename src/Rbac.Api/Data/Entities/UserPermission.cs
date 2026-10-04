namespace Rbac.Api.Data.Entities;

/// <summary>Join table: permissions granted directly to a user, in addition to their roles.</summary>
public class UserPermission
{
    public string UserId { get; set; } = null!;

    public int PermissionId { get; set; }

    public AppUser User { get; set; } = null!;

    public Permission Permission { get; set; } = null!;
}
