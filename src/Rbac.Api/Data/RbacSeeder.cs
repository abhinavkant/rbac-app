using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data.Entities;

namespace Rbac.Api.Data;

/// <summary>
/// Seeds the RBAC graph: permissions -> roles -> users, plus one user with a direct permission grant
/// and a few orders so the endpoints have something to return.
/// </summary>
public sealed class RbacSeeder(
    RbacDbContext dbContext,
    IPasswordHasher<AppUser> passwordHasher,
    ILogger<RbacSeeder> logger)
{
    /// <summary>The role -> permission bundles. Changing a line here changes what roles can do.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> RolePermissions =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [RoleNames.Administrator] = [.. Permissions.All],
            [RoleNames.Manager] =
            [
                Permissions.UsersRead,
                Permissions.UsersUpdate,
                Permissions.OrdersRead,
                Permissions.OrdersCreate,
                Permissions.OrdersCancel,
                Permissions.ReportsRead,
                Permissions.ReportsExport
            ],
            [RoleNames.Support] =
            [
                Permissions.UsersRead,
                Permissions.OrdersRead,
                Permissions.OrdersCancel
            ],
            [RoleNames.Viewer] = [Permissions.OrdersRead],
            [RoleNames.Auditor] = [Permissions.ReportsRead]
        };

    /// <summary>
    /// Demo accounts. Shared with the integration tests so both sides stay in sync.
    /// </summary>
    public static readonly SeedUser[] SeedUsers =
    [
        new("admin@rbac.dev", "Admin!Pass123", "Ada", "Admin", [RoleNames.Administrator], []),
        new("manager@rbac.dev", "Manager!Pass123", "Manny", "Manager", [RoleNames.Manager], []),
        new("support@rbac.dev", "Support!Pass123", "Sam", "Support", [RoleNames.Support], []),
        // A Viewer that can export reports because the permission is granted to the user itself -
        // no new role, no code change.
        new("viewer@rbac.dev", "Viewer!Pass123", "Vera", "Viewer", [RoleNames.Viewer], [Permissions.ReportsExport]),
        new("auditor@rbac.dev", "Auditor!Pass123", "Aud", "Auditor", [RoleNames.Auditor], [])
    ];

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        if (await dbContext.Roles.AnyAsync(cancellationToken))
        {
            logger.LogInformation("RBAC data already present, skipping seed.");
            return;
        }

        // 1. Permissions: the catalog of things that can be done.
        var permissions = Permissions.All
            .Select(name => new Permission { Name = name })
            .ToList();

        dbContext.Permissions.AddRange(permissions);
        await dbContext.SaveChangesAsync(cancellationToken);

        // 2. Roles: named bundles of permissions.
        var roles = new List<Role>();
        foreach ((string roleName, string[] permissionNames) in RolePermissions)
        {
            var role = new Role { Name = roleName };

            foreach (string name in permissionNames)
            {
                role.RolePermissions.Add(new RolePermission { Permission = FindPermission(permissions, name) });
            }

            roles.Add(role);
        }

        dbContext.Roles.AddRange(roles);
        await dbContext.SaveChangesAsync(cancellationToken);

        // 3. Users: assigned to roles, optionally with extra permissions of their own.
        foreach (SeedUser seedUser in SeedUsers)
        {
            var user = new AppUser
            {
                Id = Guid.NewGuid().ToString(),
                Email = seedUser.Email,
                PasswordHash = passwordHasher.HashPassword(null!, seedUser.Password),
                FirstName = seedUser.FirstName,
                LastName = seedUser.LastName,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };

            foreach (string roleName in seedUser.Roles)
            {
                user.UserRoles.Add(new UserRole { Role = FindRole(roles, roleName) });
            }

            foreach (string name in seedUser.DirectPermissions)
            {
                user.UserPermissions.Add(new UserPermission { Permission = FindPermission(permissions, name) });
            }

            dbContext.Users.Add(user);
        }

        // 4. A little data for the orders and reports endpoints.
        dbContext.Orders.AddRange(
            new Order
            {
                CustomerEmail = "customer@example.com",
                Description = "Mechanical keyboard",
                Total = 149.00m,
                Status = OrderStatus.Placed,
                CreatedAt = DateTimeOffset.UtcNow.AddDays(-2)
            },
            new Order
            {
                CustomerEmail = "customer@example.com",
                Description = "Ultrawide monitor",
                Total = 899.50m,
                Status = OrderStatus.Shipped,
                CreatedAt = DateTimeOffset.UtcNow.AddDays(-1)
            },
            new Order
            {
                CustomerEmail = "another@example.com",
                Description = "USB-C dock",
                Total = 219.99m,
                Status = OrderStatus.Delivered,
                CreatedAt = DateTimeOffset.UtcNow.AddDays(-5)
            });

        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Seeded {PermissionCount} permissions, {RoleCount} roles and {UserCount} users.",
            permissions.Count,
            roles.Count,
            SeedUsers.Length);
    }

    private static Permission FindPermission(List<Permission> permissions, string name)
        => permissions.First(permission => permission.Name == name);

    private static Role FindRole(List<Role> roles, string name)
        => roles.First(role => string.Equals(role.Name, name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Demo account definition.</summary>
public sealed record SeedUser(
    string Email,
    string Password,
    string FirstName,
    string LastName,
    string[] Roles,
    string[] DirectPermissions);
