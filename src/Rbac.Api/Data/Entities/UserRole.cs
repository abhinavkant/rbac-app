namespace Rbac.Api.Data.Entities;

/// <summary>Join table: which roles a user has.</summary>
public class UserRole
{
    public string UserId { get; set; } = null!;

    public int RoleId { get; set; }

    public AppUser User { get; set; } = null!;

    public Role Role { get; set; } = null!;
}
