using System.Net.Http.Json;
using Rbac.Api.Data;

namespace Rbac.Api.Tests.Infrastructure;

public static class TestUsers
{
    /// <summary>The seeded account that holds the given role.</summary>
    public static SeedUser WithRole(string roleName) =>
        RbacSeeder.SeedUsers.First(user => user.Roles.Contains(roleName, StringComparer.OrdinalIgnoreCase));

    public static SeedUser Admin => WithRole(RoleNames.Administrator);

    public static SeedUser Manager => WithRole(RoleNames.Manager);

    public static SeedUser Support => WithRole(RoleNames.Support);

    /// <summary>Viewer plus a direct grants:export permission, so it can export reports but not manage them.</summary>
    public static SeedUser Viewer => WithRole(RoleNames.Viewer);

    public static SeedUser Auditor => WithRole(RoleNames.Auditor);

    public static async Task<HttpClient> LoginAsync(RbacApiFactory factory, SeedUser user)
    {
        HttpClient client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync("/auth/login", new { email = user.Email, password = user.Password });
        response.EnsureSuccessStatusCode();

        var login = await response.Content.ReadFromJsonAsync<Login>();

        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login!.AccessToken);

        return client;
    }

    public static async Task<string> FindUserIdAsync(HttpClient adminClient, string email)
    {
        var users = await adminClient.GetFromJsonAsync<UserResponse[]>("/users");

        return users!.Single(user => user.Email == email).Id;
    }

    private sealed record Login(string AccessToken);

    public sealed record UserResponse(string Id, string Email, string[] Roles, string[] DirectPermissions);
}
