using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The "who can do what" query behind <c>Server</c> mode: a role bundle plus whatever was granted to
/// the user directly, deduplicated. Getting this wrong is silent - the request simply gets a 403.
/// </summary>
public sealed class EfPermissionServiceTests
{
    [Fact]
    public async Task A_user_gets_the_permissions_of_their_roles()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        string[] permissions = await service.GetPermissionsAsync(await IdOfAsync(database, TestEmail(RoleNames.Manager)));

        Assert.Equal<IEnumerable<string>>(
            RbacSeeder.RolePermissions[RoleNames.Manager].OrderBy(permission => permission),
            permissions);
    }

    [Fact]
    public async Task Direct_grants_are_added_to_the_role_permissions()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        // The seeded Viewer holds orders:read through its role and reports:export directly.
        string[] permissions = await service.GetPermissionsAsync(await IdOfAsync(database, TestEmail(RoleNames.Viewer)));

        Assert.Equal<IEnumerable<string>>(
            new[] { Permissions.OrdersRead, Permissions.ReportsExport }.OrderBy(permission => permission),
            permissions);
    }

    [Fact]
    public async Task A_permission_held_twice_is_reported_once()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        AppUser user = await database.DbContext.Users
            .Include(user => user.UserRoles)
            .Include(user => user.UserPermissions)
            .SingleAsync(user => user.Email == TestEmail(RoleNames.Viewer));

        // Grant the Viewer orders:read directly as well: it already has it through the role.
        var viewerRole = await database.DbContext.Roles.SingleAsync(role => role.Name == RoleNames.Viewer);
        var ordersRead = await database.DbContext.Permissions.SingleAsync(permission => permission.Name == Permissions.OrdersRead);

        database.DbContext.UserPermissions.Add(new UserPermission { User = user, Permission = ordersRead });
        await database.DbContext.SaveChangesAsync();

        string[] permissions = await service.GetPermissionsAsync(user.Id);

        Assert.Equal<IEnumerable<string>>(
            new[] { Permissions.OrdersRead, Permissions.ReportsExport },
            permissions.OrderBy(permission => permission));

        Assert.Single(permissions, permission => permission == Permissions.OrdersRead);
        Assert.NotEmpty(viewerRole.RolePermissions);
    }

    [Fact]
    public async Task Permissions_from_several_roles_are_merged()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        AppUser user = await CreateUserAsync(database, email: "both@rbac.dev", roles: [RoleNames.Viewer, RoleNames.Auditor]);

        string[] permissions = await service.GetPermissionsAsync(user.Id);

        Assert.Equal<IEnumerable<string>>(
            new[] { Permissions.OrdersRead, Permissions.ReportsRead }.OrderBy(permission => permission),
            permissions);
    }

    [Fact]
    public async Task The_result_is_sorted_so_it_can_be_cached_and_compared()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        string[] permissions = await service.GetPermissionsAsync(await IdOfAsync(database, TestEmail(RoleNames.Administrator)));

        Assert.Equal<IEnumerable<string>>(permissions.OrderBy(permission => permission), permissions);
        Assert.Equal(Permissions.All.Count, permissions.Length);
    }

    [Fact]
    public async Task An_unknown_user_resolves_to_no_permissions()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        Assert.Empty(await service.GetPermissionsAsync("no-such-user"));
    }

    [Fact]
    public async Task A_user_without_roles_or_grants_resolves_to_no_permissions()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        AppUser user = await CreateUserAsync(database, email: "nobody@rbac.dev", roles: []);

        Assert.Empty(await service.GetPermissionsAsync(user.Id));
    }

    [Fact]
    public async Task Roles_are_resolved_in_order_and_deduplicated()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        AppUser user = await CreateUserAsync(database, email: "sorted@rbac.dev", roles: [RoleNames.Viewer, RoleNames.Auditor, RoleNames.Manager]);

        string[] roles = await service.GetRolesAsync(user.Id);

        Assert.Equal<IEnumerable<string>>(new[] { RoleNames.Auditor, RoleNames.Manager, RoleNames.Viewer }, roles);
    }

    [Fact]
    public async Task Removing_a_role_removes_its_permissions()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        AppUser user = await CreateUserAsync(database, email: "revoke@rbac.dev", roles: [RoleNames.Manager]);

        Assert.NotEmpty(await service.GetPermissionsAsync(user.Id));

        database.DbContext.UserRoles.RemoveRange(user.UserRoles);
        await database.DbContext.SaveChangesAsync();

        Assert.Empty(await service.GetPermissionsAsync(user.Id));
    }

    [Fact]
    public async Task Deleting_a_user_removes_the_role_assignment_too()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var service = new EfPermissionService(database.DbContext);

        AppUser user = await CreateUserAsync(database, email: "cascade@rbac.dev", roles: [RoleNames.Viewer]);

        database.DbContext.Users.Remove(user);
        await database.DbContext.SaveChangesAsync();

        Assert.False(await database.DbContext.UserRoles.AnyAsync(userRole => userRole.UserId == user.Id));
        Assert.Empty(await service.GetPermissionsAsync(user.Id));
    }

    private static string TestEmail(string roleName)
        => RbacSeeder.SeedUsers.First(user => user.Roles.Contains(roleName, StringComparer.OrdinalIgnoreCase)).Email;

    private static async Task<string> IdOfAsync(SqliteRbacDb database, string email)
        => await database.DbContext.Users
            .Where(user => user.Email == email)
            .Select(user => user.Id)
            .SingleAsync();

    private static async Task<AppUser> CreateUserAsync(SqliteRbacDb database, string email, string[] roles)
    {
        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = email,
            PasswordHash = "not-a-real-hash",
            FirstName = "Data",
            LastName = "Layer",
            CreatedAt = DateTimeOffset.UtcNow
        };

        foreach (string roleName in roles)
        {
            Role role = await database.DbContext.Roles.SingleAsync(candidate => candidate.Name == roleName);

            user.UserRoles.Add(new UserRole { Role = role });
        }

        database.DbContext.Users.Add(user);
        await database.DbContext.SaveChangesAsync();

        return user;
    }
}
