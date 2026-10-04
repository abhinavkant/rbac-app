using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Hybrid;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;

namespace Rbac.Api.Features.Users;

/// <summary>
/// User administration. Notice that not a single action asks "is this user an Administrator?" - every
/// action states the permission it needs. Changing who is an Administrator is then a data change, not a
/// code change.
/// </summary>
[ApiController]
[Route("users")]
[Tags("Users")]
public sealed class UserController(RbacDbContext dbContext, HybridCache permissionCache) : RbacControllerBase
{
    /// <summary>Lists users. Requires users:read.</summary>
    [HttpGet]
    [Authorize(Policy = Permissions.UsersRead)]
    [EndpointSummary("Lists users. Requires users:read.")]
    [ProducesResponseType<UserResponse[]>(StatusCodes.Status200OK)]
    public async Task<ActionResult<UserResponse[]>> ListAsync(CancellationToken cancellationToken)
    {
        AppUser[] users = await dbContext.Users
            .AsNoTracking()
            .Include(user => user.UserRoles).ThenInclude(userRole => userRole.Role)
            .Include(user => user.UserPermissions).ThenInclude(userPermission => userPermission.Permission)
            .OrderBy(user => user.Email)
            .ToArrayAsync(cancellationToken);

        UserResponse[] response = [.. users.Select(ToResponse)];

        return Ok(response);
    }

    /// <summary>Gets a single user. Requires users:read.</summary>
    [HttpGet("{id}")]
    [Authorize(Policy = Permissions.UsersRead)]
    [EndpointSummary("Gets a single user. Requires users:read.")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserResponse>> GetAsync(string id, CancellationToken cancellationToken)
    {
        AppUser? user = await FindUserAsync(id, cancellationToken);

        return user is null
            ? Problem(title: "User not found", detail: $"No user with id '{id}'.", statusCode: StatusCodes.Status404NotFound)
            : Ok(ToResponse(user));
    }

    /// <summary>Creates a user. Requires users:create.</summary>
    [HttpPost]
    [Authorize(Policy = Permissions.UsersCreate)]
    [EndpointSummary("Creates a user. Requires users:create.")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<UserResponse>> CreateAsync(
        [FromBody] CreateUserRequest request,
        IPasswordHasher<AppUser> passwordHasher,
        IAuthorizationCatalog catalog,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email)
            || string.IsNullOrWhiteSpace(request.Password)
            || string.IsNullOrWhiteSpace(request.FirstName)
            || string.IsNullOrWhiteSpace(request.LastName))
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["request"] = ["Email, password, first name and last name are required."]
            });
        }

        string email = request.Email.Trim();

        if (await dbContext.Users.AnyAsync(user => user.Email == email, cancellationToken))
        {
            return Problem(
                title: "Email already in use",
                detail: $"A user with email '{email}' already exists.",
                statusCode: StatusCodes.Status409Conflict);
        }

        string[] roleNames = request.Roles ?? [];
        string[] permissionNames = request.Permissions ?? [];

        IReadOnlyList<string> unknownRoles = await catalog.FindUnknownRolesAsync(roleNames, cancellationToken);
        if (unknownRoles.Count > 0)
        {
            IReadOnlyList<string> knownRoles = await catalog.GetKnownRolesAsync(cancellationToken);

            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["roles"] = [$"Unknown role(s): {string.Join(", ", unknownRoles)}. Known roles: {string.Join(", ", knownRoles)}."]
            });
        }

        IReadOnlyList<string> unknownPermissions = catalog.FindUnknownPermissions(permissionNames);
        if (unknownPermissions.Count > 0)
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["permissions"] = [$"Unknown permission(s): {string.Join(", ", unknownPermissions)}."]
            });
        }

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = email,
            PasswordHash = passwordHasher.HashPassword(null!, request.Password),
            FirstName = request.FirstName.Trim(),
            LastName = request.LastName.Trim(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await AttachRolesAsync(user, roleNames, cancellationToken);
        await AttachPermissionsAsync(user, permissionNames, cancellationToken);

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync(cancellationToken);

        return Created($"/users/{user.Id}", ToResponse(user));
    }

    /// <summary>Updates a user profile. Requires users:update.</summary>
    [HttpPut("{id}")]
    [Authorize(Policy = Permissions.UsersUpdate)]
    [EndpointSummary("Updates a user profile. Requires users:update.")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserResponse>> UpdateAsync(
        string id,
        [FromBody] UpdateUserRequest request,
        CancellationToken cancellationToken)
    {
        AppUser? user = await FindUserAsync(id, cancellationToken);

        if (user is null)
        {
            return Problem(title: "User not found", detail: $"No user with id '{id}'.", statusCode: StatusCodes.Status404NotFound);
        }

        if (string.IsNullOrWhiteSpace(request.FirstName) && string.IsNullOrWhiteSpace(request.LastName) && request.IsActive is null)
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["request"] = ["Provide at least one of first name, last name or active flag."]
            });
        }

        if (!string.IsNullOrWhiteSpace(request.FirstName))
        {
            user.FirstName = request.FirstName.Trim();
        }

        if (!string.IsNullOrWhiteSpace(request.LastName))
        {
            user.LastName = request.LastName.Trim();
        }

        if (request.IsActive is { } isActive)
        {
            user.IsActive = isActive;
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        return Ok(ToResponse(user));
    }

    /// <summary>Deletes a user. Requires users:delete.</summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = Permissions.UsersDelete)]
    [EndpointSummary("Deletes a user. Requires users:delete.")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteAsync(string id, CancellationToken cancellationToken)
    {
        AppUser? user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == id, cancellationToken);

        if (user is null)
        {
            return Problem(title: "User not found", detail: $"No user with id '{id}'.", statusCode: StatusCodes.Status404NotFound);
        }

        dbContext.Users.Remove(user);
        await dbContext.SaveChangesAsync(cancellationToken);

        // Drop the cached permissions so a request in flight cannot resurrect them.
        await permissionCache.RemoveAsync(PermissionCacheKeys.ForUser(id));

        return NoContent();
    }

    /// <summary>Replaces the roles of a user, which changes what they can do. Requires users:assign-roles.</summary>
    [HttpPost("{id}/roles")]
    [Authorize(Policy = Permissions.UsersAssignRoles)]
    [EndpointSummary("Replaces the roles of a user, which changes what they can do. Requires users:assign-roles.")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserResponse>> AssignRolesAsync(
        string id,
        [FromBody] AssignRolesRequest request,
        IAuthorizationCatalog catalog,
        CancellationToken cancellationToken)
    {
        AppUser? user = await FindUserAsync(id, cancellationToken);

        if (user is null)
        {
            return Problem(title: "User not found", detail: $"No user with id '{id}'.", statusCode: StatusCodes.Status404NotFound);
        }

        string[] roleNames = request.Roles ?? [];

        IReadOnlyList<string> unknownRoles = await catalog.FindUnknownRolesAsync(roleNames, cancellationToken);
        if (unknownRoles.Count > 0)
        {
            IReadOnlyList<string> knownRoles = await catalog.GetKnownRolesAsync(cancellationToken);

            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["roles"] = [$"Unknown role(s): {string.Join(", ", unknownRoles)}. Known roles: {string.Join(", ", knownRoles)}."]
            });
        }

        // Assign roles as a diff rather than "delete every join row, then re-insert them":
        //
        // - the user's existing join rows are already tracked here, and inserting a second entity for a
        //   (UserId, RoleId) pair that is still tracked throws an identity-map conflict;
        // - a diff keeps this to a single SaveChanges, so the operation stays atomic;
        // - sending the same roles again is then simply a no-op, which is what an admin clicking
        //   "save" twice expects.
        HashSet<string> requested = new(roleNames, StringComparer.OrdinalIgnoreCase);

        List<UserRole> obsolete = [.. user.UserRoles.Where(userRole => !requested.Contains(userRole.Role.Name))];

        dbContext.UserRoles.RemoveRange(obsolete);

        foreach (UserRole userRole in obsolete)
        {
            user.UserRoles.Remove(userRole);
        }

        HashSet<string> current = user.UserRoles
            .Select(userRole => userRole.Role.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        await AttachRolesAsync(user, [.. requested.Where(name => !current.Contains(name))], cancellationToken);

        await dbContext.SaveChangesAsync(cancellationToken);

        await permissionCache.RemoveAsync(PermissionCacheKeys.ForUser(id));

        return Ok(ToResponse(user));
    }

    /// <summary>Grants or revokes permissions directly on a user. Requires users:grant-permissions.</summary>
    [HttpPost("{id}/permissions")]
    [Authorize(Policy = Permissions.UsersGrantPermissions)]
    [EndpointSummary("Grants or revokes permissions directly on a user. Requires users:grant-permissions.")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserResponse>> GrantPermissionsAsync(
        string id,
        [FromBody] GrantPermissionsRequest request,
        IAuthorizationCatalog catalog,
        CancellationToken cancellationToken)
    {
        AppUser? user = await FindUserAsync(id, cancellationToken);

        if (user is null)
        {
            return Problem(title: "User not found", detail: $"No user with id '{id}'.", statusCode: StatusCodes.Status404NotFound);
        }

        string[] permissionNames = request.Permissions ?? [];

        if (permissionNames.Length == 0)
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["permissions"] = ["Provide at least one permission."]
            });
        }

        IReadOnlyList<string> unknownPermissions = catalog.FindUnknownPermissions(permissionNames);
        if (unknownPermissions.Count > 0)
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["permissions"] = [$"Unknown permission(s): {string.Join(", ", unknownPermissions)}."]
            });
        }

        var permissions = await dbContext.Permissions
            .Where(permission => permissionNames.Contains(permission.Name))
            .ToDictionaryAsync(permission => permission.Name, StringComparer.OrdinalIgnoreCase, cancellationToken);

        if (request.Revoke)
        {
            // Match on the ids: the dictionary itself cannot be translated into SQL.
            int[] permissionIds = [.. permissions.Values.Select(permission => permission.Id)];

            List<UserPermission> toRemove = await dbContext.UserPermissions
                .Where(userPermission => userPermission.UserId == id && permissionIds.Contains(userPermission.PermissionId))
                .ToListAsync(cancellationToken);

            dbContext.UserPermissions.RemoveRange(toRemove);
        }
        else
        {
            AddPermissionGrants(user, permissionNames, permissions);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        await permissionCache.RemoveAsync(PermissionCacheKeys.ForUser(id));

        // Reload so the response shows the state that was just persisted.
        AppUser updated = (await FindUserAsync(id, cancellationToken))!;

        return Ok(ToResponse(updated));
    }

    private Task<AppUser?> FindUserAsync(string id, CancellationToken cancellationToken)
        => dbContext.Users
            .Include(user => user.UserRoles).ThenInclude(userRole => userRole.Role)
            .Include(user => user.UserPermissions).ThenInclude(userPermission => userPermission.Permission)
            .FirstOrDefaultAsync(user => user.Id == id, cancellationToken);

    private async Task AttachRolesAsync(AppUser user, string[] roleNames, CancellationToken cancellationToken)
    {
        if (roleNames.Length == 0)
        {
            return;
        }

        Role[] roles = await dbContext.Roles
            .Where(role => roleNames.Contains(role.Name))
            .ToArrayAsync(cancellationToken);

        foreach (Role role in roles)
        {
            user.UserRoles.Add(new UserRole { Role = role });
        }
    }

    private async Task AttachPermissionsAsync(
        AppUser user,
        string[] permissionNames,
        CancellationToken cancellationToken)
    {
        if (permissionNames.Length == 0)
        {
            return;
        }

        Dictionary<string, Permission> permissionsByName = await dbContext.Permissions
            .Where(permission => permissionNames.Contains(permission.Name))
            .ToDictionaryAsync(permission => permission.Name, StringComparer.OrdinalIgnoreCase, cancellationToken);

        AddPermissionGrants(user, permissionNames, permissionsByName);
    }

    /// <summary>
    /// Adds a grant per permission, skipping the ones already in place so repeated calls are harmless.
    /// </summary>
    private static void AddPermissionGrants(
        AppUser user,
        IEnumerable<string> permissionNames,
        Dictionary<string, Permission> permissionsByName)
    {
        HashSet<string> existing = user.UserPermissions
            .Select(userPermission => userPermission.Permission.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (string name in permissionNames)
        {
            if (existing.Add(name) && permissionsByName.TryGetValue(name, out Permission? permission))
            {
                user.UserPermissions.Add(new UserPermission { Permission = permission });
            }
        }
    }

    private static UserResponse ToResponse(AppUser user) => new(
        user.Id,
        user.Email,
        $"{user.FirstName} {user.LastName}".Trim(),
        user.IsActive,
        [.. user.UserRoles.Select(userRole => userRole.Role.Name).OrderBy(name => name)],
        [.. user.UserPermissions.Select(userPermission => userPermission.Permission.Name).OrderBy(name => name)]);
}
