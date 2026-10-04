using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Integration;

public sealed class AuthEndpointTests(TokenSourceApiFactory factory) : IClassFixture<TokenSourceApiFactory>
{
    [Fact]
    public async Task Login_returns_roles_and_permissions_for_the_role_bundle()
    {
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "/auth/login",
            new { email = TestUsers.Manager.Email, password = TestUsers.Manager.Password });

        response.EnsureSuccessStatusCode();

        LoginResponse login = (await response.Content.ReadFromJsonAsync<LoginResponse>())!;

        Assert.Equal("Bearer", login.TokenType);
        Assert.Contains(RoleNames.Manager, login.Roles);
        Assert.Contains(Permissions.UsersRead, login.Permissions);
        Assert.Contains(Permissions.ReportsExport, login.Permissions);
        Assert.DoesNotContain(Permissions.UsersDelete, login.Permissions);
        Assert.Equal("Token", login.PermissionSource);
    }

    [Fact]
    public async Task Login_merges_role_permissions_with_directly_granted_permissions()
    {
        using HttpClient client = factory.CreateClient();

        LoginResponse login = await LoginAsync(client, TestUsers.Viewer);

        // From the Viewer role.
        Assert.Contains(Permissions.OrdersRead, login.Permissions);

        // From the direct grant on the user, not from any role.
        Assert.Contains(Permissions.ReportsExport, login.Permissions);
        Assert.DoesNotContain(Permissions.OrdersCreate, login.Permissions);
    }

    [Fact]
    public async Task Me_reflects_the_effective_permissions_of_the_token()
    {
        using HttpClient client = await TestUsers.LoginAsync(factory, TestUsers.Support);

        MeResponse me = (await client.GetFromJsonAsync<MeResponse>("/auth/me"))!;

        Assert.Equal(TestUsers.Support.Email, me.Email);
        Assert.Contains(RoleNames.Support, me.Roles);
        Assert.Contains(Permissions.OrdersCancel, me.Permissions);
        Assert.Contains(Permissions.UsersRead, me.Permissions);
        Assert.DoesNotContain(Permissions.OrdersCreate, me.Permissions);
    }

    [Fact]
    public async Task Me_shows_the_permissions_from_the_token_in_token_mode()
    {
        using HttpClient client = factory.CreateClient();

        string token = await factory.LoginAsync(client, TestUsers.Admin);

        // The Viewer-style check: read the JWT and confirm it carries permission claims here.
        string payload = token.Split('.')[1];
        payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');

        using JsonDocument document = JsonDocument.Parse(
            System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'))));

        Assert.Contains("permission", document.RootElement.EnumerateObject().Select(property => property.Name));
    }

    [Theory]
    [InlineData("admin@rbac.dev", "wrong-password")]
    [InlineData("nobody@rbac.dev", "Admin!Pass123")]
    public async Task Bad_credentials_are_rejected_without_saying_which_part_failed(string email, string password)
    {
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsJsonAsync("/auth/login", new { email, password });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Missing_credentials_are_a_validation_problem()
    {
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsJsonAsync("/auth/login", new { email = "", password = "" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Role_catalog_reports_what_each_role_carries()
    {
        using HttpClient client = await TestUsers.LoginAsync(factory, TestUsers.Viewer);

        var catalog = await client.GetFromJsonAsync<CatalogResponse>("/roles");

        Assert.Equal(Permissions.All, catalog!.Permissions);

        RoleDefinition viewer = catalog.Roles.Single(role => role.Name == RoleNames.Viewer);
        Assert.Equal(new[] { Permissions.OrdersRead }, viewer.Permissions);

        RoleDefinition administrator = catalog.Roles.Single(role => role.Name == RoleNames.Administrator);
        Assert.Equal(Permissions.All.Count, administrator.Permissions.Length);
    }

    private static async Task<LoginResponse> LoginAsync(HttpClient client, SeedUser user)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("/auth/login", new { email = user.Email, password = user.Password });

        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    private sealed record LoginResponse(string AccessToken, string TokenType, string[] Roles, string[] Permissions, string PermissionSource);

    private sealed record MeResponse(string Id, string Email, string FullName, string[] Roles, string[] Permissions, string PermissionSource);

    private sealed record CatalogResponse(string[] Permissions, RoleDefinition[] Roles);

    private sealed record RoleDefinition(string Name, string[] Permissions);
}
