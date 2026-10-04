using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Rbac.Api.Authorization;
using Rbac.Api.Security;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The 401 and 403 responses are the only feedback an API caller gets, so their contents are part of
/// the contract. These tests drive the events directly against a bare <see cref="HttpContext"/>.
/// </summary>
public sealed class RbacJwtBearerEventsTests
{
    private static readonly RbacJwtBearerEvents Events = new();

    [Fact]
    public async Task A_challenge_is_a_401_problem_document_with_a_bearer_header()
    {
        DefaultHttpContext httpContext = CreateContext();

        await Events.Challenge(Challenge(httpContext));

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.Equal("application/problem+json", httpContext.Response.ContentType);
        Assert.Equal(new[] { "Bearer" }, httpContext.Response.Headers[HeaderNames.WWWAuthenticate].ToArray());

        JsonElement problem = await ReadProblemAsync(httpContext);

        Assert.Equal("Unauthorized", problem.GetProperty("title").GetString());
        Assert.Equal(401, problem.GetProperty("status").GetInt32());
        Assert.Equal("trace-123", problem.GetProperty("traceId").GetString());
    }

    [Theory]
    [InlineData(typeof(SecurityTokenExpiredException), "has expired")]
    [InlineData(typeof(SecurityTokenException), "is not valid")]
    [InlineData(null, "requires a valid bearer token")]
    public async Task The_challenge_detail_explains_why_the_token_was_rejected(Type? failureType, string expected)
    {
        DefaultHttpContext httpContext = CreateContext();

        await Events.Challenge(Challenge(httpContext, failureType is null ? null : (Exception)Activator.CreateInstance(failureType)!));

        Assert.Contains(expected, (await ReadProblemAsync(httpContext)).GetProperty("detail").GetString());
    }

    [Fact]
    public async Task A_challenge_never_leaks_the_permissions_of_an_unauthenticated_caller()
    {
        DefaultHttpContext httpContext = CreateContext();

        httpContext.User = Principal(Permissions.UsersRead);

        await Events.Challenge(Challenge(httpContext));

        JsonElement problem = await ReadProblemAsync(httpContext);

        Assert.False(problem.TryGetProperty("grantedPermissions", out _));
    }

    [Fact]
    public async Task A_forbidden_is_a_403_problem_document_listing_the_granted_permissions()
    {
        DefaultHttpContext httpContext = CreateContext();

        httpContext.User = Principal(Permissions.OrdersRead, Permissions.ReportsExport);

        await Events.Forbidden(Forbidden(httpContext));

        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        Assert.Equal("application/problem+json", httpContext.Response.ContentType);

        JsonElement problem = await ReadProblemAsync(httpContext);

        Assert.Equal("Forbidden", problem.GetProperty("title").GetString());
        Assert.Equal(403, problem.GetProperty("status").GetInt32());
        Assert.Equal("trace-123", problem.GetProperty("traceId").GetString());

        string[] granted = [.. problem.GetProperty("grantedPermissions").EnumerateArray().Select(item => item.GetString()!)];

        Assert.Equal<IEnumerable<string>>(new[] { Permissions.OrdersRead, Permissions.ReportsExport }, granted);
    }

    [Fact]
    public async Task A_forbidden_omits_the_permission_list_when_the_caller_has_none()
    {
        DefaultHttpContext httpContext = CreateContext();

        await Events.Forbidden(Forbidden(httpContext));

        JsonElement problem = await ReadProblemAsync(httpContext);

        Assert.Equal(403, problem.GetProperty("status").GetInt32());
        Assert.False(problem.TryGetProperty("grantedPermissions", out _));
    }

    /// <summary>
    /// A context with a writable body, a trace id and the services the problem+json writer needs - the
    /// app gets those from <c>AddProblemDetails()</c> in <c>Program.cs</c>.
    /// </summary>
    private static DefaultHttpContext CreateContext() => new()
    {
        TraceIdentifier = "trace-123",
        RequestServices = Services.Value,
        Response = { Body = new MemoryStream() }
    };

    /// <summary>The problem+json writer needs logging and <see cref="IProblemDetailsService"/>, exactly
    /// as <c>Program.cs</c> wires them up for the running app.</summary>
    private static readonly Lazy<ServiceProvider> Services = new(() => new ServiceCollection()
        .AddLogging()
        .AddProblemDetails()
        .BuildServiceProvider());

    private static JwtBearerChallengeContext Challenge(HttpContext httpContext, Exception? failure = null)
    {
        var context = new JwtBearerChallengeContext(httpContext, Scheme(), BearerOptions(), new AuthenticationProperties())
        {
            AuthenticateFailure = failure
        };

        return context;
    }

    private static ForbiddenContext Forbidden(HttpContext httpContext)
        => new(httpContext, Scheme(), BearerOptions());

    private static AuthenticationScheme Scheme() => new("Bearer", null, typeof(JwtBearerHandler));

    private static JwtBearerOptions BearerOptions() => Options.Create(new JwtBearerOptions()).Value;

    private static ClaimsPrincipal Principal(params string[] permissions)
    {
        Claim[] claims = [.. permissions.Select(permission => new Claim(CustomClaimTypes.Permission, permission))];

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Test"));
    }

    private static async Task<JsonElement> ReadProblemAsync(HttpContext httpContext)
    {
        httpContext.Response.Body.Position = 0;

        using var reader = new StreamReader(httpContext.Response.Body);

        using JsonDocument document = JsonDocument.Parse(await reader.ReadToEndAsync());

        return document.RootElement.Clone();
    }
}
