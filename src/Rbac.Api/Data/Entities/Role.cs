using System.ComponentModel.DataAnnotations;

namespace Rbac.Api.Data.Entities;

public class Role
{
    public int Id { get; set; }

    [MaxLength(100)]
    public required string Name { get; set; }

    public ICollection<RolePermission> RolePermissions { get; } = [];

    public ICollection<UserRole> UserRoles { get; } = [];
}
