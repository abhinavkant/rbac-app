namespace Rbac.Api.Data.Entities;

/// <summary>Join table: which permissions a role carries. Editing this table is how you change RBAC.</summary>
public class RolePermission
{
    public int RoleId { get; set; }

    public int PermissionId { get; set; }

    public Role Role { get; set; } = null!;

    public Permission Permission { get; set; } = null!;
}
