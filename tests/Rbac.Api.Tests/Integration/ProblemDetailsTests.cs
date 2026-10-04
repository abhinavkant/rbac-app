using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Rbac.Api.Authorization;
using Rbac.Api.Tests.Infrastructure;

namespace Rbac.Api.Tests.Integration;

/// <summary>
/// 401 and 403 come back as RFC 7807 problem documents instead of an empty body, which is what makes
/// "why was I rejected?" answerable.
/// </summary>
public sealed class ProblemDetailsTests(TokenSourceApiFactory factory) : IClassFixture<TokenSourceApiFactory>
{
    [Fact]
    public async Task Unauthorized_response_is_a_problem_document()
    {
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/users");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        JsonElement problem = await ReadProblemAsync(response);

        Assert.Equal("Unauthorized", problem.GetProperty("title").GetString());
        Assert.Equal(401, problem.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("traceId").GetString()));
    }

    [Fact]
    public async Task Forbidden_response_lists_the_permissions_the_caller_does_have()
    {
        using HttpClient client = await TestUsers.LoginAsync(factory, TestUsers.Viewer);

        using HttpResponseMessage response = await client.GetAsync("/users");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        JsonElement problem = await ReadProblemAsync(response);

        Assert.Equal("Forbidden", problem.GetProperty("title").GetString());
        Assert.Equal(403, problem.GetProperty("status").GetInt32());

        // This is the debugging hint: the caller can see what they do hold.
        string[] granted = [.. problem.GetProperty("grantedPermissions").EnumerateArray().Select(item => item.GetString()!)];

        Assert.Contains(Permissions.OrdersRead, granted);
        Assert.DoesNotContain(Permissions.UsersRead, granted);
    }

    [Fact]
    public async Task A_tampered_token_is_unauthorized()
    {
        using HttpClient client = factory.CreateClient();

        string token = await factory.LoginAsync(client, TestUsers.Admin);

        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token[..^4] + "AAAA");

        using HttpResponseMessage response = await client.GetAsync("/users");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Unknown_role_in_a_request_is_a_validation_problem()
    {
        using HttpClient admin = await TestUsers.LoginAsync(factory, TestUsers.Admin);

        using HttpResponseMessage response = await admin.PostAsJsonAsync(
            "/users",
            new
            {
                email = $"wizard-{Guid.NewGuid():N}@rbac.dev",
                password = "Wizard!Pass123",
                firstName = "The",
                lastName = "Wizard",
                roles = new[] { "Wizard" }
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        JsonElement problem = await ReadProblemAsync(response);

        Assert.True(problem.GetProperty("errors").GetProperty("roles")[0].GetString()!.Contains("Wizard", StringComparison.Ordinal));
    }

    private static async Task<JsonElement> ReadProblemAsync(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
}
