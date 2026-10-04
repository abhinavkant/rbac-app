using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Rbac.Api.Authorization;

namespace Rbac.Api.Tests.Unit;

public sealed class PermissionAuthorizationRequirementTests
{
    [Fact]
    public async Task Any_mode_succeeds_when_one_permission_matches()
    {
        var requirement = new PermissionAuthorizationRequirement(Permissions.UsersRead, Permissions.UsersUpdate);
        AuthorizationHandlerContext context = CreateContext(requirement, Permissions.UsersUpdate);

        await requirement.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Any_mode_fails_when_no_permission_matches()
    {
        var requirement = new PermissionAuthorizationRequirement(Permissions.UsersRead, Permissions.UsersUpdate);
        AuthorizationHandlerContext context = CreateContext(requirement, Permissions.OrdersRead);

        await requirement.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task All_mode_requires_every_permission()
    {
        var requirement = new PermissionAuthorizationRequirement(
            PermissionMatchMode.All,
            Permissions.ReportsRead,
            Permissions.ReportsExport);

        AuthorizationHandlerContext partial = CreateContext(requirement, Permissions.ReportsRead);
        await requirement.HandleAsync(partial);
        Assert.False(partial.HasSucceeded);

        AuthorizationHandlerContext complete = CreateContext(requirement, Permissions.ReportsRead, Permissions.ReportsExport);
        await requirement.HandleAsync(complete);
        Assert.True(complete.HasSucceeded);
    }

    [Fact]
    public async Task Roles_alone_do_not_authorize_anything()
    {
        // The whole point of the pattern: role claims are not permissions.
        var requirement = new PermissionAuthorizationRequirement(Permissions.UsersRead);

        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Role, "Administrator")],
            authenticationType: "Test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role);

        AuthorizationHandlerContext context = new([requirement], new ClaimsPrincipal(identity), resource: null);

        await requirement.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task An_unauthenticated_principal_is_never_authorized()
    {
        var requirement = new PermissionAuthorizationRequirement(Permissions.UsersRead);
        AuthorizationHandlerContext context = new([requirement], new ClaimsPrincipal(), resource: null);

        await requirement.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public void Permissions_are_trimmed_and_deduplicated()
    {
        var requirement = new PermissionAuthorizationRequirement(" users:read ", "users:read", "users:update");

        Assert.Equal([Permissions.UsersRead, Permissions.UsersUpdate], requirement.AllowedPermissions);
        Assert.Equal(PermissionMatchMode.Any, requirement.Mode);
        Assert.False(requirement.RequiresAllPermissions);
    }

    [Fact]
    public void An_empty_permission_list_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new PermissionAuthorizationRequirement());
        Assert.Throws<ArgumentException>(() => new PermissionAuthorizationRequirement("  "));
    }

    private static AuthorizationHandlerContext CreateContext(PermissionAuthorizationRequirement requirement, params string[] permissions)
    {
        var claims = permissions
            .Select(permission => new Claim(CustomClaimTypes.Permission, permission))
            .ToArray();

        var identity = new ClaimsIdentity(claims, authenticationType: "Test");

        // The context has to hold the very requirement instance under test: Succeed() targets it.
        return new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(identity), resource: null);
    }
}
