using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The catalog turns a typo in a request into a 400 instead of a silent no-op or a 500.
/// </summary>
public sealed class DatabaseAuthorizationCatalogTests
{
    [Fact]
    public async Task Known_permissions_come_from_the_code_catalog()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync();

        Assert.Equal<IEnumerable<string>>(Permissions.All, Catalog(database).KnownPermissions);
    }

    [Fact]
    public async Task The_known_roles_are_read_from_the_database()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        IReadOnlyList<string> roles = await Catalog(database).GetKnownRolesAsync();

        Assert.Equal(
            new[] { RoleNames.Administrator, RoleNames.Auditor, RoleNames.Manager, RoleNames.Support, RoleNames.Viewer },
            roles);
    }

    [Fact]
    public async Task An_empty_database_knows_no_roles()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync();

        Assert.Empty(await Catalog(database).GetKnownRolesAsync());
    }

    [Theory]
    [InlineData("Manager")]
    [InlineData("manager")]
    [InlineData("  Manager  ")]
    public async Task A_known_role_is_recognised_regardless_of_case_and_padding(string candidate)
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        Assert.Empty(await Catalog(database).FindUnknownRolesAsync([candidate]));
    }

    [Fact]
    public async Task Unknown_roles_are_reported_once_each()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        IReadOnlyList<string> unknown = await Catalog(database).FindUnknownRolesAsync(
            [RoleNames.Manager, "Wizard", "wizard", "  Wizard  ", "Manager"]);

        Assert.Equal<IEnumerable<string>>(["Wizard"], unknown);
    }

    [Fact]
    public async Task Blank_entries_are_not_reported_as_unknown_roles()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        Assert.Empty(await Catalog(database).FindUnknownRolesAsync([string.Empty, "   "]));
    }

    [Fact]
    public async Task No_roles_at_all_is_not_an_error()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        IAuthorizationCatalog catalog = Catalog(database);

        Assert.Empty(await catalog.FindUnknownRolesAsync(null));
        Assert.Empty(await catalog.FindUnknownRolesAsync([]));
    }

    [Fact]
    public async Task A_role_that_is_in_the_code_but_not_in_the_database_is_unknown()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync();

        Assert.Equal<IEnumerable<string>>([RoleNames.Manager], await Catalog(database).FindUnknownRolesAsync([RoleNames.Manager]));
    }

    [Fact]
    public async Task The_catalog_sees_a_role_created_after_it_was_built()
    {
        await using SqliteRbacDb database = await SqliteRbacDb.CreateAsync(seed: true);

        IAuthorizationCatalog catalog = Catalog(database);

        Assert.Equal<IEnumerable<string>>(["Editor"], await catalog.FindUnknownRolesAsync(["Editor"]));

        database.DbContext.Roles.Add(new Role { Name = "Editor" });
        await database.DbContext.SaveChangesAsync();

        Assert.Empty(await catalog.FindUnknownRolesAsync(["Editor"]));
    }

    [Fact]
    public void A_permission_outside_the_catalog_is_unknown()
    {
        IAuthorizationCatalog catalog = new DatabaseAuthorizationCatalog(null!);

        Assert.Equal(["orders:delete"], catalog.FindUnknownPermissions(["orders:delete"]));
        Assert.Empty(catalog.FindUnknownPermissions([Permissions.OrdersCancel, Permissions.UsersRead]));
        Assert.Empty(catalog.FindUnknownPermissions(null));
    }

    [Fact]
    public void Permission_names_are_trimmed_before_they_are_compared()
    {
        IAuthorizationCatalog catalog = new DatabaseAuthorizationCatalog(null!);

        Assert.Empty(catalog.FindUnknownPermissions([$"  {Permissions.UsersRead}  "]));
    }

    [Fact]
    public void Permission_names_are_recognised_regardless_of_case()
    {
        IAuthorizationCatalog catalog = new DatabaseAuthorizationCatalog(null!);

        Assert.Empty(catalog.FindUnknownPermissions(["USERS:READ"]));
    }

    [Fact]
    public void Unknown_permissions_are_reported_once_each()
    {
        IAuthorizationCatalog catalog = new DatabaseAuthorizationCatalog(null!);

        Assert.Equal(["orders:delete", "reports:purge"], catalog.FindUnknownPermissions(["orders:delete", "reports:purge", "ORDERS:DELETE"]));
    }

    private static IAuthorizationCatalog Catalog(SqliteRbacDb database) => new DatabaseAuthorizationCatalog(database.DbContext);
}
