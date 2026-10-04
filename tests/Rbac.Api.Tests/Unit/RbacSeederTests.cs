using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The seeded RBAC graph is the fixture the integration tests and the README matrix rely on, so its
/// invariants are asserted here rather than discovered by a confusing 403 later.
/// </summary>
public sealed class RbacSeederTests
{
    [Fact]
    public void The_administrator_role_carries_every_permission()
        => Assert.Equal<IEnumerable<string>>(Permissions.All.OrderBy(permission => permission), Bundle(RoleNames.Administrator));

    [Fact]
    public void No_role_carries_a_permission_that_is_not_in_the_catalog()
    {
        foreach ((string roleName, string[] permissions) in RbacSeeder.RolePermissions)
        {
            Assert.True(permissions.Length > 0, $"Role '{roleName}' carries no permissions at all.");

            Assert.All(permissions, permission => Assert.Contains(permission, Permissions.All));
        }
    }

    [Fact]
    public void A_bundle_never_lists_the_same_permission_twice()
    {
        Assert.All(
            RbacSeeder.RolePermissions,
            bundle => Assert.Equal(bundle.Value.Length, bundle.Value.Distinct(StringComparer.Ordinal).Count()));
    }

    [Fact]
    public void Every_permission_in_the_catalog_is_reachable_through_some_role()
    {
        string[] covered = [.. RbacSeeder.RolePermissions.Values.SelectMany(permissions => permissions).Distinct()];

        Assert.Equal<IEnumerable<string>>(Permissions.All.OrderBy(permission => permission), covered.OrderBy(permission => permission));
    }

    [Theory]
    [InlineData(RoleNames.Viewer, Permissions.UsersRead)]
    [InlineData(RoleNames.Auditor, Permissions.OrdersCreate)]
    [InlineData(RoleNames.Support, Permissions.UsersDelete)]
    public void A_role_does_not_carry_a_permission_it_is_not_meant_to(string roleName, string permission)
        => Assert.DoesNotContain(permission, Bundle(roleName));

    [Fact]
    public void Every_demo_user_has_at_least_one_known_role()
    {
        Assert.All(RbacSeeder.SeedUsers, seedUser =>
        {
            Assert.NotEmpty(seedUser.Roles);
            Assert.All(seedUser.Roles, role => Assert.Contains(role, RbacSeeder.RolePermissions.Keys));
            Assert.All(seedUser.DirectPermissions, permission => Assert.Contains(permission, Permissions.All));
        });
    }

    [Fact]
    public void Every_demo_account_has_a_password()
        => Assert.All(RbacSeeder.SeedUsers, seedUser => Assert.False(string.IsNullOrWhiteSpace(seedUser.Password)));

    [Fact]
    public void The_demo_emails_are_unique()
    {
        string[] emails = [.. RbacSeeder.SeedUsers.Select(seedUser => seedUser.Email)];

        Assert.Equal(emails.Length, emails.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public async Task Seeding_creates_the_catalog_the_roles_the_users_and_the_orders()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync();

        await database.SeedAsync();

        Assert.Equal(Permissions.All.Count, await database.DbContext.Permissions.CountAsync());
        Assert.Equal(RbacSeeder.RolePermissions.Count, await database.DbContext.Roles.CountAsync());
        Assert.Equal(RbacSeeder.SeedUsers.Length, await database.DbContext.Users.CountAsync());
        Assert.Equal(3, await database.DbContext.Orders.CountAsync());
    }

    [Fact]
    public async Task Each_seeded_user_resolves_to_its_roles_plus_its_direct_grants()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        var permissionService = new EfPermissionService(database.DbContext);

        foreach (SeedUser seedUser in RbacSeeder.SeedUsers)
        {
            AppUser user = await database.DbContext.Users.SingleAsync(candidate => candidate.Email == seedUser.Email);

            string[] expected =
            [
                .. seedUser.Roles
                    .SelectMany(roleName => RbacSeeder.RolePermissions[roleName])
                    .Concat(seedUser.DirectPermissions)
                    .Distinct()
                    .OrderBy(permission => permission)
            ];

            Assert.Equal<IEnumerable<string>>(expected, await permissionService.GetPermissionsAsync(user.Id));
            Assert.Equal<IEnumerable<string>>(seedUser.Roles.OrderBy(role => role), await permissionService.GetRolesAsync(user.Id));
        }
    }

    [Fact]
    public async Task The_viewer_demo_account_can_export_reports_without_holding_a_role_for_it()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        SeedUser viewer = RbacSeeder.SeedUsers.Single(user => user.Email.Contains("viewer", StringComparison.OrdinalIgnoreCase));

        AppUser user = await database.DbContext.Users
            .Include(user => user.UserRoles)
            .ThenInclude(userRole => userRole.Role)
            .ThenInclude(role => role.RolePermissions)
            .SingleAsync(candidate => candidate.Email == viewer.Email);

        Assert.Equal<IEnumerable<string>>(viewer.DirectPermissions, user.UserPermissions.Select(grant => grant.Permission.Name));

        // The permission comes from the user, not from the role bundle.
        Assert.DoesNotContain(Permissions.ReportsExport, Bundle(RoleNames.Viewer));
    }

    [Fact]
    public async Task Seeding_twice_changes_nothing()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync();

        await database.SeedAsync();

        int permissions = await database.DbContext.Permissions.CountAsync();
        int users = await database.DbContext.Users.CountAsync();

        await database.SeedAsync();

        Assert.Equal(permissions, await database.DbContext.Permissions.CountAsync());
        Assert.Equal(users, await database.DbContext.Users.CountAsync());
    }

    private static string[] Bundle(string roleName)
        => RbacSeeder.RolePermissions.TryGetValue(roleName, out string[]? permissions)
            ? [.. permissions.OrderBy(permission => permission)]
            : throw new InvalidOperationException($"Role '{roleName}' is not seeded.");
}
