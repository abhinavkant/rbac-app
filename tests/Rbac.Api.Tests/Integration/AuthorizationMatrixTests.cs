using System.Net;
using System.Net.Http.Json;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Integration;

/// <summary>
/// The point of the sample, in table form: the same URL answers 401 / 403 / 200 depending on which
/// permissions the caller's token carries.
/// </summary>
public sealed class AuthorizationMatrixTests(TokenSourceApiFactory factory) : IClassFixture<TokenSourceApiFactory>
{
    public static TheoryData<string, HttpMethod, string, HttpStatusCode> Endpoints => new()
    {
        // users:read - Support, Manager and Administrator have it, Viewer and Auditor do not.
        { RoleNames.Viewer, HttpMethod.Get, "/users", HttpStatusCode.Forbidden },
        { RoleNames.Auditor, HttpMethod.Get, "/users", HttpStatusCode.Forbidden },
        { RoleNames.Support, HttpMethod.Get, "/users", HttpStatusCode.OK },
        { RoleNames.Manager, HttpMethod.Get, "/users", HttpStatusCode.OK },
        { RoleNames.Administrator, HttpMethod.Get, "/users", HttpStatusCode.OK },

        // users:create - administrators only.
        { RoleNames.Manager, HttpMethod.Post, "/users", HttpStatusCode.Forbidden },
        { RoleNames.Administrator, HttpMethod.Post, "/users", HttpStatusCode.BadRequest },

        // orders:read
        { RoleNames.Viewer, HttpMethod.Get, "/orders", HttpStatusCode.OK },
        { RoleNames.Auditor, HttpMethod.Get, "/orders", HttpStatusCode.Forbidden },
        { RoleNames.Support, HttpMethod.Get, "/orders", HttpStatusCode.OK },

        // orders:create
        { RoleNames.Viewer, HttpMethod.Post, "/orders", HttpStatusCode.Forbidden },
        { RoleNames.Support, HttpMethod.Post, "/orders", HttpStatusCode.Forbidden },
        { RoleNames.Manager, HttpMethod.Post, "/orders", HttpStatusCode.Created },

        // orders:cancel - passing the permission check with no such order ends in 404.
        { RoleNames.Viewer, HttpMethod.Post, "/orders/404404/cancel", HttpStatusCode.Forbidden },
        { RoleNames.Support, HttpMethod.Post, "/orders/404404/cancel", HttpStatusCode.NotFound },

        // reports:read
        { RoleNames.Auditor, HttpMethod.Get, "/reports/summary", HttpStatusCode.OK },
        { RoleNames.Viewer, HttpMethod.Get, "/reports/summary", HttpStatusCode.Forbidden },

        // reports:export - the Viewer holds it as a direct grant rather than through a role.
        { RoleNames.Auditor, HttpMethod.Get, "/reports/export", HttpStatusCode.Forbidden },
        { RoleNames.Viewer, HttpMethod.Get, "/reports/export", HttpStatusCode.OK },
        { RoleNames.Manager, HttpMethod.Get, "/reports/export", HttpStatusCode.OK },

        // reports:read AND reports:export
        { RoleNames.Viewer, HttpMethod.Get, "/reports/full", HttpStatusCode.Forbidden },
        { RoleNames.Support, HttpMethod.Get, "/reports/full", HttpStatusCode.Forbidden },
        { RoleNames.Manager, HttpMethod.Get, "/reports/full", HttpStatusCode.OK }
    };

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task Endpoint_is_gated_by_permission_not_by_role_name(
        string role,
        HttpMethod method,
        string url,
        HttpStatusCode expected)
    {
        using HttpClient client = await TestUsers.LoginAsync(factory, TestUsers.WithRole(role));

        using var request = new HttpRequestMessage(method, url);

        if (method == HttpMethod.Post)
        {
            request.Content = JsonContent.Create(NewOrder());
        }

        using HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(expected, response.StatusCode);
    }

    [Theory]
    [InlineData("/users")]
    [InlineData("/orders")]
    [InlineData("/reports/summary")]
    [InlineData("/reports/export")]
    [InlineData("/auth/me")]
    public async Task Protected_endpoint_without_a_token_is_unauthorized(string url)
    {
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.GetAsync(url);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", response.Headers.WwwAuthenticate.Single().Scheme);
    }

    [Fact]
    public async Task Login_is_anonymous()
    {
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "/auth/login",
            new { email = TestUsers.Admin.Email, password = TestUsers.Admin.Password });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Role_catalog_requires_a_token_but_no_permission()
    {
        using HttpClient anonymous = factory.CreateClient();
        using HttpResponseMessage anonymousResponse = await anonymous.GetAsync("/roles");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        using HttpClient viewer = await TestUsers.LoginAsync(factory, TestUsers.Viewer);
        using HttpResponseMessage response = await viewer.GetAsync("/roles");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Cancelling_an_order_needs_orders_cancel()
    {
        using HttpClient manager = await TestUsers.LoginAsync(factory, TestUsers.Manager);
        using HttpClient support = await TestUsers.LoginAsync(factory, TestUsers.Support);
        using HttpClient viewer = await TestUsers.LoginAsync(factory, TestUsers.Viewer);

        using HttpResponseMessage created = await manager.PostAsJsonAsync("/orders", NewOrder());
        created.EnsureSuccessStatusCode();

        int orderId = (await created.Content.ReadFromJsonAsync<OrderResponse>())!.Id;

        using (HttpResponseMessage forbidden = await viewer.PostAsync($"/orders/{orderId}/cancel", null))
        {
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        using HttpResponseMessage cancelled = await support.PostAsync($"/orders/{orderId}/cancel", null);

        Assert.Equal(HttpStatusCode.OK, cancelled.StatusCode);
        Assert.Equal("Cancelled", (await cancelled.Content.ReadFromJsonAsync<OrderResponse>())!.Status);
    }

    [Fact]
    public async Task Deleting_a_user_requires_the_delete_permission()
    {
        using HttpClient admin = await TestUsers.LoginAsync(factory, TestUsers.Admin);
        using HttpClient manager = await TestUsers.LoginAsync(factory, TestUsers.Manager);

        string email = $"throwaway-{Guid.NewGuid():N}@rbac.dev";
        string userId = await CreateUserAsync(admin, email, "Throwaway!Pass123", [RoleNames.Viewer], []);

        using (HttpResponseMessage forbidden = await manager.DeleteAsync($"/users/{userId}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }

        using HttpResponseMessage response = await admin.DeleteAsync($"/users/{userId}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Assigning_roles_changes_what_the_user_can_do()
    {
        using HttpClient admin = await TestUsers.LoginAsync(factory, TestUsers.Admin);

        string email = $"promote-me-{Guid.NewGuid():N}@rbac.dev";
        string password = "PromoteMe!Pass123";
        string userId = await CreateUserAsync(admin, email, password, [RoleNames.Auditor], []);

        // An Auditor cannot read users.
        using (HttpClient auditor = await LoginNewUserAsync(factory, email, password))
        {
            using HttpResponseMessage before = await auditor.GetAsync("/users");
            Assert.Equal(HttpStatusCode.Forbidden, before.StatusCode);
        }

        using (HttpResponseMessage assigned = await admin.PostAsJsonAsync(
                   $"/users/{userId}/roles",
                   new { roles = new[] { RoleNames.Manager } }))
        {
            Assert.Equal(HttpStatusCode.OK, assigned.StatusCode);
        }

        // Same account, new role: the endpoint code did not change.
        using (HttpClient manager = await LoginNewUserAsync(factory, email, password))
        {
            using HttpResponseMessage after = await manager.GetAsync("/users");
            Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        }
    }

    [Fact]
    public async Task Granting_a_permission_directly_widens_access_without_a_new_role()
    {
        using HttpClient admin = await TestUsers.LoginAsync(factory, TestUsers.Admin);

        string email = $"grantee-{Guid.NewGuid():N}@rbac.dev";
        string password = "Grantee!Pass123";
        string userId = await CreateUserAsync(admin, email, password, [RoleNames.Viewer], []);

        using (HttpClient grantee = await LoginNewUserAsync(factory, email, password))
        {
            using HttpResponseMessage before = await grantee.PostAsJsonAsync("/orders", NewOrder());
            Assert.Equal(HttpStatusCode.Forbidden, before.StatusCode);
        }

        using (HttpResponseMessage grant = await admin.PostAsJsonAsync(
                   $"/users/{userId}/permissions",
                   new { permissions = new[] { Permissions.OrdersCreate }, revoke = false }))
        {
            Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
        }

        using (HttpClient grantee = await LoginNewUserAsync(factory, email, password))
        {
            using HttpResponseMessage after = await grantee.PostAsJsonAsync("/orders", NewOrder());
            Assert.Equal(HttpStatusCode.Created, after.StatusCode);
        }

        using (HttpResponseMessage revoke = await admin.PostAsJsonAsync(
                   $"/users/{userId}/permissions",
                   new { permissions = new[] { Permissions.OrdersCreate }, revoke = true }))
        {
            Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        }

        using (HttpClient grantee = await LoginNewUserAsync(factory, email, password))
        {
            using HttpResponseMessage afterRevoke = await grantee.PostAsJsonAsync("/orders", NewOrder());
            Assert.Equal(HttpStatusCode.Forbidden, afterRevoke.StatusCode);
        }
    }

    [Fact]
    public async Task Assigning_the_same_roles_twice_is_harmless()
    {
        using HttpClient admin = await TestUsers.LoginAsync(factory, TestUsers.Admin);

        string email = $"idempotent-{Guid.NewGuid():N}@rbac.dev";
        string userId = await CreateUserAsync(admin, email, "Idempotent!Pass123", [RoleNames.Viewer], []);

        for (int attempt = 1; attempt <= 2; attempt++)
        {
            using HttpResponseMessage response = await admin.PostAsJsonAsync(
                $"/users/{userId}/roles",
                new { roles = new[] { RoleNames.Viewer, RoleNames.Auditor } });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var user = await response.Content.ReadFromJsonAsync<UserResponse>();

            Assert.Equal(new[] { RoleNames.Auditor, RoleNames.Viewer }, user!.Roles.OrderBy(role => role));
        }

        // Dropping a role from the set still works.
        using HttpResponseMessage narrowed = await admin.PostAsJsonAsync(
            $"/users/{userId}/roles",
            new { roles = new[] { RoleNames.Auditor } });

        narrowed.EnsureSuccessStatusCode();

        Assert.Equal(new[] { RoleNames.Auditor }, (await narrowed.Content.ReadFromJsonAsync<UserResponse>())!.Roles);
    }

    private static async Task<string> CreateUserAsync(HttpClient admin, string email, string password, string[] roles, string[] permissions)
    {
        using HttpResponseMessage response = await admin.PostAsJsonAsync(
            "/users",
            new
            {
                email,
                password,
                firstName = "Created",
                lastName = "User",
                roles,
                permissions
            });

        response.EnsureSuccessStatusCode();

        var created = await response.Content.ReadFromJsonAsync<UserResponse>();

        return created!.Id;
    }

    private static async Task<HttpClient> LoginNewUserAsync(RbacApiFactory factory, string email, string password)
    {
        using HttpClient anonymous = factory.CreateClient();

        using HttpResponseMessage response = await anonymous.PostAsJsonAsync("/auth/login", new { email, password });
        response.EnsureSuccessStatusCode();

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();

        HttpClient client = factory.CreateClient();
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

    private sealed record UserResponse(string Id, string Email, string[] Roles, string[] DirectPermissions);

    private sealed record OrderResponse(int Id, string Status);
}
