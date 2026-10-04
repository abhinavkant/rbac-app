using Rbac.Api.Authorization;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The catalog is the vocabulary of the whole authorization system: a typo here silently disables an
/// endpoint, so its shape and its helpers are worth pinning down.
/// </summary>
public sealed class PermissionsTests
{
    [Fact]
    public void The_catalog_has_no_duplicates()
        => Assert.Equal(Permissions.All.Count, Permissions.All.Distinct(StringComparer.Ordinal).Count());

    [Fact]
    public void Every_permission_is_written_as_resource_colon_action()
    {
        Assert.All(Permissions.All, permission => Assert.Matches("^[a-z]+:[a-z]+(-[a-z]+)*$", permission));
    }

    [Fact]
    public void Splitting_and_joining_round_trips()
    {
        Assert.All(
            Permissions.All,
            permission => Assert.Equal(
                permission,
                $"{Permissions.GetResource(permission)}:{Permissions.GetAction(permission)}"));
    }

    [Fact]
    public void GetResource_and_GetAction_split_a_permission()
    {
        Assert.Equal("users", Permissions.GetResource(Permissions.UsersRead));
        Assert.Equal("read", Permissions.GetAction(Permissions.UsersRead));
    }

    [Theory]
    [InlineData("users", "users", "")]
    [InlineData("users:", "users", "")]
    [InlineData("users:read:all", "users", "read:all")]
    public void Unusual_names_split_without_throwing(string permission, string resource, string action)
    {
        Assert.Equal(resource, Permissions.GetResource(permission));
        Assert.Equal(action, Permissions.GetAction(permission));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void A_blank_permission_is_rejected(string permission)
    {
        Assert.Throws<ArgumentException>(() => Permissions.GetResource(permission));
        Assert.Throws<ArgumentException>(() => Permissions.GetAction(permission));
    }

    [Fact]
    public void The_catalog_groups_permissions_by_resource()
    {
        string[] resources = [.. Permissions.All.Select(Permissions.GetResource).Distinct()];

        Assert.Equal(["orders", "reports", "users"], resources.OrderBy(resource => resource));
    }
}
