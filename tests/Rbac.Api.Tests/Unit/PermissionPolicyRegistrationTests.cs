using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Api.Authorization;
using Rbac.Api.Configuration;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// MVC actions authorize with <c>[Authorize(Policy = ...)]</c>, and .NET 10 resolves that string through
/// the policy provider - there is no hook left on <c>AuthorizeAttribute</c> to build a policy inline. So the
/// policy registration is the contract between the attribute and the handler, and it is asserted here.
/// </summary>
public sealed class PermissionPolicyRegistrationTests
{
    [Fact]
    public async Task Every_permission_in_the_catalog_has_a_policy_named_after_it()
    {
        IAuthorizationPolicyProvider provider = CreatePolicyProvider();

        foreach (string permission in Permissions.All)
        {
            AuthorizationPolicy? policy = await provider.GetPolicyAsync(permission);

            Assert.NotNull(policy);
            Assert.Equal(permission, Assert.Single(RequirementOf(policy!).AllowedPermissions));
        }
    }

    [Fact]
    public async Task Every_registered_policy_also_demands_an_authenticated_user()
    {
        // Without this the anonymous caller would be told 403 Forbidden instead of 401 Unauthorized: a named
        // policy replaces the default policy rather than adding to it.
        IAuthorizationPolicyProvider provider = CreatePolicyProvider();

        AuthorizationPolicy policy = (await provider.GetPolicyAsync(Permissions.UsersRead))!;

        Assert.Contains(policy.Requirements, requirement => requirement is DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task An_unknown_policy_name_resolves_to_nothing()
    {
        IAuthorizationPolicyProvider provider = CreatePolicyProvider();

        Assert.Null(await provider.GetPolicyAsync("users:purge"));
        Assert.Null(await provider.GetPolicyAsync(""));
    }

    [Fact]
    public async Task The_policy_for_a_permission_admits_a_caller_holding_it()
    {
        IAuthorizationService service = CreateAuthorizationService();
        AuthorizationPolicy policy = (await CreatePolicyProvider().GetPolicyAsync(Permissions.OrdersCancel))!;

        var allowed = await service.AuthorizeAsync(Principal(Permissions.OrdersCancel), resource: null, policy);
        var denied = await service.AuthorizeAsync(Principal(Permissions.OrdersRead), resource: null, policy);
        var anonymous = await service.AuthorizeAsync(new ClaimsPrincipal(), resource: null, policy);

        Assert.True(allowed.Succeeded);
        Assert.False(denied.Succeeded);
        Assert.False(anonymous.Succeeded);
    }

    [Fact]
    public async Task The_combined_report_policy_requires_both_permissions()
    {
        IAuthorizationPolicyProvider provider = CreatePolicyProvider();

        AuthorizationPolicy policy = (await provider.GetPolicyAsync(PermissionPolicies.ReportsReadAndExport))!;

        PermissionAuthorizationRequirement requirement = RequirementOf(policy);

        Assert.Equal(PermissionMatchMode.All, requirement.Mode);
        Assert.Equal(new[] { Permissions.ReportsRead, Permissions.ReportsExport }, requirement.AllowedPermissions);
        Assert.Contains(policy.Requirements, candidate => candidate is DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task The_combined_report_policy_admits_only_a_caller_holding_both()
    {
        IAuthorizationService service = CreateAuthorizationService();
        AuthorizationPolicy policy = (await CreatePolicyProvider().GetPolicyAsync(PermissionPolicies.ReportsReadAndExport))!;

        Assert.False((await service.AuthorizeAsync(Principal(Permissions.ReportsRead), resource: null, policy)).Succeeded);
        Assert.True((await service.AuthorizeAsync(
            Principal(Permissions.ReportsRead, Permissions.ReportsExport),
            resource: null,
            policy)).Succeeded);
    }

    [Fact]
    public void The_composed_policy_name_cannot_collide_with_a_permission_name()
    {
        string[] names = [.. Permissions.All, PermissionPolicies.ReportsReadAndExport];

        Assert.Equal(names.Length, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task A_composed_policy_name_can_be_built_for_permissions_outside_the_catalog()
    {
        // Attribute arguments have to be constants, which is why names like this one are declared up front
        // rather than composed at the call site.
        Assert.Equal("orders:read+orders:cancel", PermissionPolicies.AllOf(Permissions.OrdersRead, Permissions.OrdersCancel));
        Assert.Null(await CreatePolicyProvider().GetPolicyAsync(PermissionPolicies.AllOf(Permissions.OrdersRead, Permissions.OrdersCancel)));
    }

    private static PermissionAuthorizationRequirement RequirementOf(AuthorizationPolicy policy)
        => Assert.IsType<PermissionAuthorizationRequirement>(
            Assert.Single(policy.Requirements.OfType<PermissionAuthorizationRequirement>()));

    private static ServiceProvider CreateServices()
        => new ServiceCollection()
            .AddLogging()
            .AddRbacAuthorization(new ConfigurationBuilder().Build())
            // DatabaseAuthorizationCatalog is registered by AddRbacAuthorization but never resolved here.
            .AddSingleton(new Microsoft.Data.Sqlite.SqliteConnection("Filename=:memory:"))
            .BuildServiceProvider();

    private static IAuthorizationPolicyProvider CreatePolicyProvider()
        => CreateServices().GetRequiredService<IAuthorizationPolicyProvider>();

    private static IAuthorizationService CreateAuthorizationService()
        => CreateServices().GetRequiredService<IAuthorizationService>();

    private static ClaimsPrincipal Principal(params string[] permissions)
    {
        Claim[] claims = [.. permissions.Select(permission => new Claim(CustomClaimTypes.Permission, permission))];

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Test", nameType: ClaimTypes.Name, roleType: ClaimTypes.Role));
    }
}
