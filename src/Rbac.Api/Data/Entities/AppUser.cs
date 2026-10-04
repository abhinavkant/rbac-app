using System.ComponentModel.DataAnnotations;

namespace Rbac.Api.Data.Entities;

public class AppUser
{
    public required string Id { get; set; }

    [MaxLength(320)]
    public required string Email { get; set; }

    [MaxLength(512)]
    public required string PasswordHash { get; set; }

    [MaxLength(100)]
    public required string FirstName { get; set; }

    [MaxLength(100)]
    public required string LastName { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Roles the user belongs to. Each role carries a set of permissions.</summary>
    public ICollection<UserRole> UserRoles { get; } = [];

    /// <summary>
    /// Permissions granted straight to the user, bypassing roles. This is the extension point for
    /// "this one person also needs X" without inventing a new role.
    /// </summary>
    public ICollection<UserPermission> UserPermissions { get; } = [];
}
