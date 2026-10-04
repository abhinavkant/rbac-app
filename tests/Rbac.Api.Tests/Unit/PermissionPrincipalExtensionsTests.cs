using System.Security.Claims;
using Rbac.Api.Authorization;
using Rbac.Api.Data;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The claim helpers used by the handler, by the claims transformation and by the 403 problem document.
/// </summary>
public sealed class PermissionPrincipalExtensionsTests
{
    [Fact]
    public void GetPermissions_reads_every_permission_claim()
    {
        ClaimsPrincipal principal = Principal(Permissions.UsersRead, Permissions.OrdersRead);

        Assert.Equal<IEnumerable<string>>(
            new[] { Permissions.OrdersRead, Permissions.UsersRead },
            principal.GetPermissions().OrderBy(permission => permission));
    }

    [Fact]
    public void GetPermissions_ignores_other_claims()
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(CustomClaimTypes.Permission, Permissions.UsersRead),
                new Claim(ClaimTypes.Role, RoleNames.Administrator),
                new Claim("email", "someone@rbac.dev")
            ],
            authenticationType: "Test");

        Assert.Equal<IEnumerable<string>>(new[] { Permissions.UsersRead }, new ClaimsPrincipal(identity).GetPermissions());
    }

    [Fact]
    public void An_anonymous_principal_has_no_permissions()
        => Assert.Empty(new ClaimsPrincipal().GetPermissions());

    [Fact]
    public void HasPermission_matches_the_exact_claim_value()
    {
        ClaimsPrincipal principal = Principal(Permissions.UsersRead);

        Assert.True(principal.HasPermission(Permissions.UsersRead));
        Assert.False(principal.HasPermission(Permissions.UsersUpdate));
    }

    [Fact]
    public void Permission_names_are_case_sensitive()
    {
        // Deliberate: a case-insensitive check would silently accept "Users:Read" and hide a typo in a
        // role bundle, which is the failure mode this whole pattern exists to avoid.
        ClaimsPrincipal principal = Principal(Permissions.UsersRead);

        Assert.False(principal.HasPermission("Users:Read"));
    }

    [Fact]
    public void Role_claims_are_not_permissions()
    {
        Claim[] roleClaims = [new Claim(ClaimTypes.Role, RoleNames.Administrator)];

        var identity = new ClaimsIdentity(
            roleClaims,
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role,
            authenticationType: "Test");

        ClaimsPrincipal principal = new(identity);

        Assert.False(principal.HasPermission(Permissions.UsersDelete));
        Assert.Empty(principal.GetPermissions());
    }

    [Fact]
    public void HasAllPermissions_needs_every_permission()
    {
        ClaimsPrincipal principal = Principal(Permissions.ReportsRead, Permissions.ReportsExport);

        Assert.True(principal.HasAllPermissions(Permissions.ReportsRead, Permissions.ReportsExport));
        Assert.False(principal.HasAllPermissions(Permissions.ReportsRead, Permissions.OrdersCancel));
    }

    [Fact]
    public void HasAllPermissions_agrees_with_the_all_mode_requirement()
    {
        ClaimsPrincipal principal = Principal(Permissions.ReportsRead, Permissions.ReportsExport);

        Assert.Equal(
            principal.HasAllPermissions(Permissions.ReportsRead, Permissions.ReportsExport),
            new PermissionAuthorizationRequirement(
                    PermissionMatchMode.All,
                    Permissions.ReportsRead,
                    Permissions.ReportsExport)
                .AllowedPermissions.All(principal.HasPermission));
    }

    [Fact]
    public void Null_arguments_are_rejected()
    {
        ClaimsPrincipal principal = Principal(Permissions.UsersRead);

        Assert.Throws<ArgumentNullException>(() => ((ClaimsPrincipal)null!).GetPermissions());
        Assert.Throws<ArgumentException>(() => principal.HasPermission(" "));
        Assert.Throws<ArgumentNullException>(() => principal.HasAllPermissions(null!));
    }

    private static ClaimsPrincipal Principal(params string[] permissions)
    {
        Claim[] claims = [.. permissions.Select(permission => new Claim(CustomClaimTypes.Permission, permission))];

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Test"));
    }
}
