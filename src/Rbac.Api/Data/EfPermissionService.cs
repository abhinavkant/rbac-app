using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;

namespace Rbac.Api.Data;

/// <summary>
/// Resolves permissions with a single join over the role assignments plus a second query for the
/// permissions granted directly to the user. This is the "who can do what" query; it is what the
/// <see cref="PermissionClaimsTransformation"/> caches in <c>Server</c> mode.
/// </summary>
public sealed class EfPermissionService(RbacDbContext dbContext) : IPermissionService
{
    public async Task<string[]> GetPermissionsAsync(string userId, CancellationToken cancellationToken = default)
    {
        var throughRoles =
            from userRole in dbContext.UserRoles.AsNoTracking()
            where userRole.UserId == userId
            join rolePermission in dbContext.RolePermissions.AsNoTracking() on userRole.RoleId equals rolePermission.RoleId
            join permission in dbContext.Permissions.AsNoTracking() on rolePermission.PermissionId equals permission.Id
            select permission.Name;

        var grantedDirectly =
            from userPermission in dbContext.UserPermissions.AsNoTracking()
            where userPermission.UserId == userId
            join permission in dbContext.Permissions.AsNoTracking() on userPermission.PermissionId equals permission.Id
            select permission.Name;

        return await throughRoles
            .Concat(grantedDirectly)
            .Distinct()
            .OrderBy(name => name)
            .ToArrayAsync(cancellationToken);
    }

    public async Task<string[]> GetRolesAsync(string userId, CancellationToken cancellationToken = default)
    {
        // Distinct() has to come before OrderBy(), otherwise the ordering is applied before the
        // duplicates are removed and the result comes back in join order.
        return await (
            from userRole in dbContext.UserRoles.AsNoTracking()
            where userRole.UserId == userId
            join role in dbContext.Roles.AsNoTracking() on userRole.RoleId equals role.Id
            select role.Name)
            .Distinct()
            .OrderBy(name => name)
            .ToArrayAsync(cancellationToken);
    }
}
