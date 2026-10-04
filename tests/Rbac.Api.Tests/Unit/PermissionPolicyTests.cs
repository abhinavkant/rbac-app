using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Api.Authorization;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// Exercises the requirement through the real authorization pipeline, the same way a policy built by
/// <c>RequirePermission(...)</c> is evaluated at request time.
/// </summary>
public sealed class PermissionPolicyTests
{
    [Fact]
    public async Task RequirePermission_policy_passes_with_one_of_the_permissions()
    {
        IAuthorizationService service = CreateAuthorizationService();
        AuthorizationPolicy policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequirePermission(Permissions.UsersRead, Permissions.UsersCreate)
            .Build();

        var allowed = await service.AuthorizeAsync(Principal(Permissions.UsersCreate), resource: null, policy);
        var denied = await service.AuthorizeAsync(Principal(Permissions.OrdersRead), resource: null, policy);

        Assert.True(allowed.Succeeded);
        Assert.False(denied.Succeeded);
    }

    [Fact]
    public async Task RequireAllPermissions_policy_needs_every_permission()
    {
        IAuthorizationService service = CreateAuthorizationService();
        AuthorizationPolicy policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireAllPermissions(Permissions.ReportsRead, Permissions.ReportsExport)
            .Build();

        var readOnly = await service.AuthorizeAsync(Principal(Permissions.ReportsRead), resource: null, policy);
        var complete = await service.AuthorizeAsync(
            Principal(Permissions.ReportsRead, Permissions.ReportsExport),
            resource: null,
            policy);

        Assert.False(readOnly.Succeeded);
        Assert.True(complete.Succeeded);
    }

    [Fact]
    public void Extension_methods_put_a_permission_requirement_on_the_policy()
    {
        AuthorizationPolicy anyPolicy = new AuthorizationPolicyBuilder()
            .RequirePermission(Permissions.UsersRead, Permissions.UsersUpdate)
            .Build();

        var anyRequirement = Assert.IsType<PermissionAuthorizationRequirement>(Assert.Single(anyPolicy.Requirements));
        Assert.Equal(PermissionMatchMode.Any, anyRequirement.Mode);
        Assert.Equal(new[] { Permissions.UsersRead, Permissions.UsersUpdate }, anyRequirement.AllowedPermissions);

        AuthorizationPolicy allPolicy = new AuthorizationPolicyBuilder()
            .RequireAllPermissions(Permissions.ReportsRead, Permissions.ReportsExport)
            .Build();

        var allRequirement = Assert.IsType<PermissionAuthorizationRequirement>(Assert.Single(allPolicy.Requirements));
        Assert.Equal(PermissionMatchMode.All, allRequirement.Mode);
        Assert.True(allRequirement.RequiresAllPermissions);
    }

    [Fact]
    public async Task A_denied_result_reports_that_the_requirement_was_not_met()
    {
        IAuthorizationService service = CreateAuthorizationService();
        AuthorizationPolicy policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequirePermission(Permissions.UsersDelete)
            .Build();

        AuthorizationResult result = await service.AuthorizeAsync(Principal(Permissions.UsersRead), resource: null, policy);

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
    }

    private static IAuthorizationService CreateAuthorizationService()
        => new ServiceCollection()
            .AddLogging()
            .AddAuthorization()
            .BuildServiceProvider()
            .GetRequiredService<IAuthorizationService>();

    private static ClaimsPrincipal Principal(params string[] permissions)
    {
        Claim[] claims = [.. permissions.Select(permission => new Claim(CustomClaimTypes.Permission, permission))];

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Test", nameType: ClaimTypes.Name, roleType: ClaimTypes.Role));
    }
}
