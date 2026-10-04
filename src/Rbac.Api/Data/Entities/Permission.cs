using System.ComponentModel.DataAnnotations;

namespace Rbac.Api.Data.Entities;

/// <summary>A permission such as "users:read". Rows in this table are the catalog.</summary>
public class Permission
{
    public int Id { get; set; }

    [MaxLength(100)]
    public required string Name { get; set; }

    public ICollection<RolePermission> RolePermissions { get; } = [];

    public ICollection<UserPermission> UserPermissions { get; } = [];
}
