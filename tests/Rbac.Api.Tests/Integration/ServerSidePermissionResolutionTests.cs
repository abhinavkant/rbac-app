using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Integration;

/// <summary>
/// The second permission source: the token carries roles only and permissions are resolved per request
/// by the claims transformation. The authorization code is identical; only the plumbing changes.
/// </summary>
public sealed class ServerSidePermissionResolutionTests : IAsyncLifetime
{
    private readonly ServerSourceApiFactory _factory = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public Task DisposeAsync()
    {
        _factory.Dispose();

        return Task.CompletedTask;
    }

    [Fact]
    public async Task Token_stays_small_because_permissions_are_not_embedded()
    {
        using HttpClient client = _factory.CreateClient();

        string token = await _factory.LoginAsync(client, TestUsers.Admin);

        string payload = token.Split('.')[1];
        payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');

        using JsonDocument document = JsonDocument.Parse(
            System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'))));

        string[] claimNames = [.. document.RootElement.EnumerateObject().Select(property => property.Name)];

        Assert.Contains("sub", claimNames);
        Assert.DoesNotContain(CustomClaimTypes.Permission, claimNames);
    }

    [Fact]
    public async Task Permissions_still_authorize_the_request()
    {
        using HttpClient admin = await TestUsers.LoginAsync(_factory, TestUsers.Admin);
        using HttpClient viewer = await TestUsers.LoginAsync(_factory, TestUsers.Viewer);

        using HttpResponseMessage allowed = await admin.GetAsync("/users");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);

        using HttpResponseMessage forbidden = await viewer.GetAsync("/users");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
    }

    [Fact]
    public async Task Me_reports_the_resolved_permissions_and_the_source()
    {
        using HttpClient client = await TestUsers.LoginAsync(_factory, TestUsers.Viewer);

        var me = await client.GetFromJsonAsync<MeResponse>("/auth/me");

        Assert.Equal("Server", me!.PermissionSource);
        Assert.Contains(Permissions.ReportsExport, me.Permissions);
    }

    [Fact]
    public async Task A_permission_change_takes_effect_without_asking_for_a_new_token()
    {
        using HttpClient admin = await TestUsers.LoginAsync(_factory, TestUsers.Admin);

        string email = $"live-{Guid.NewGuid():N}@rbac.dev";
        const string password = "Live!Pass123";

        using HttpResponseMessage created = await admin.PostAsJsonAsync(
            "/users",
            new
            {
                email,
                password,
                firstName = "Live",
                lastName = "Grant",
                roles = new[] { RoleNames.Viewer },
                permissions = Array.Empty<string>()
            });

        created.EnsureSuccessStatusCode();

        string userId = (await created.Content.ReadFromJsonAsync<UserResponse>())!.Id;

        using HttpClient client = await LoginAsync(email, password);

        using (HttpResponseMessage before = await client.PostAsJsonAsync("/orders", NewOrder()))
        {
            Assert.Equal(HttpStatusCode.Forbidden, before.StatusCode);
        }

        // Same token as before - only the database changed.
        using (HttpResponseMessage grant = await admin.PostAsJsonAsync(
                   $"/users/{userId}/permissions",
                   new { permissions = new[] { Permissions.OrdersCreate }, revoke = false }))
        {
            Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
        }

        using (HttpResponseMessage after = await client.PostAsJsonAsync("/orders", NewOrder()))
        {
            Assert.Equal(HttpStatusCode.Created, after.StatusCode);
        }

        // And the revocation is immediate too.
        using (HttpResponseMessage revoke = await admin.PostAsJsonAsync(
                   $"/users/{userId}/permissions",
                   new { permissions = new[] { Permissions.OrdersCreate }, revoke = true }))
        {
            Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        }

        using (HttpResponseMessage afterRevoke = await client.PostAsJsonAsync("/orders", NewOrder()))
        {
            Assert.Equal(HttpStatusCode.Forbidden, afterRevoke.StatusCode);
        }
    }

    private async Task<HttpClient> LoginAsync(string email, string password)
    {
        HttpClient client = _factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsJsonAsync("/auth/login", new { email, password });
        response.EnsureSuccessStatusCode();

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();

        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login!.AccessToken);

        return client;
    }

    private static object NewOrder() => new
    {
        customerEmail = "someone@example.com",
        description = "test order",
        total = 42m
    };

    private sealed record LoginResponse(string AccessToken);

    private sealed record UserResponse(string Id);

    private sealed record MeResponse(string PermissionSource, string[] Permissions);
}
