using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Security;

namespace Rbac.Api.Tests.Unit;

/// <summary>
/// The token is where the permission claims travel in <see cref="PermissionSource.Token"/> mode, so
/// these tests read the JWT the way a client would: decode the payload, look at the claim names.
/// </summary>
public sealed class TokenServiceTests
{
    private const string SigningKey = "unit-test-signing-key-0123456789-abcdefghij";

    [Fact]
    public void Token_mode_carries_the_permissions_and_the_roles()
    {
        AccessToken token = CreateAccessToken(PermissionSource.Token);

        JsonElement payload = ReadPayload(token.Token);

        Assert.Equal<IEnumerable<string>>(
            new[] { Permissions.OrdersRead, Permissions.UsersRead },
            PermissionClaims(payload).OrderBy(permission => permission));

        Assert.Equal<IEnumerable<string>>(new[] { RoleNames.Manager }, Roles(payload));
    }

    [Fact]
    public void The_token_identifies_the_user_by_sub_and_email()
    {
        JsonElement payload = ReadPayload(CreateAccessToken(PermissionSource.Token).Token);

        Assert.Equal("user-1", payload.GetProperty("sub").GetString());
        Assert.Equal("user@rbac.dev", payload.GetProperty("email").GetString());
    }

    [Fact]
    public void Server_mode_leaves_the_permissions_out_of_the_token()
    {
        JsonElement payload = ReadPayload(CreateAccessToken(PermissionSource.Server).Token);

        Assert.Empty(PermissionClaims(payload));

        // The user is still identifiable, so the server-side resolver can find them.
        Assert.Equal("user-1", payload.GetProperty("sub").GetString());
    }

    [Fact]
    public void Every_token_gets_its_own_token_id()
    {
        string first = Jti(CreateAccessToken(PermissionSource.Token).Token);
        string second = Jti(CreateAccessToken(PermissionSource.Token).Token);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void The_reported_expiration_matches_the_configured_lifetime()
    {
        AccessToken token = CreateAccessToken(PermissionSource.Token, expirationInMinutes: 15);

        Assert.Equal(15 * 60, token.ExpiresInSeconds);
        Assert.InRange(token.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(14), DateTimeOffset.UtcNow.AddMinutes(16));

        long expiry = ReadPayload(token.Token).GetProperty("exp").GetInt64();

        Assert.InRange(expiry, DateTimeOffset.UtcNow.AddMinutes(14).ToUnixTimeSeconds(), DateTimeOffset.UtcNow.AddMinutes(16).ToUnixTimeSeconds());
    }

    [Fact]
    public async Task The_token_validates_with_the_configured_key_issuer_and_audience()
    {
        AccessToken token = CreateAccessToken(PermissionSource.Token);

        TokenValidationResult result = await ValidateAsync(token.Token, SigningKey);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task The_token_is_rejected_when_it_was_signed_with_another_key()
    {
        AccessToken token = CreateAccessToken(PermissionSource.Token);

        TokenValidationResult result = await ValidateAsync(token.Token, "a-completely-different-signing-key-0123456789");

        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenSignatureKeyNotFoundException>(result.Exception);
    }

    [Fact]
    public void Null_arguments_are_rejected()
    {
        var service = CreateService(PermissionSource.Token);

        Assert.Throws<ArgumentNullException>(() => service.CreateAccessToken(null!, [], []));
        Assert.Throws<ArgumentNullException>(() => service.CreateAccessToken(User(), null!, []));
        Assert.Throws<ArgumentNullException>(() => service.CreateAccessToken(User(), [], null!));
    }

    private static AccessToken CreateAccessToken(PermissionSource source, int expirationInMinutes = 30)
        => CreateService(source, expirationInMinutes).CreateAccessToken(
            User(),
            [RoleNames.Manager],
            [Permissions.UsersRead, Permissions.OrdersRead]);

    private static TokenService CreateService(PermissionSource source, int expirationInMinutes = 30)
    {
        JwtOptions jwtOptions = new()
        {
            Issuer = "rbac-issuer",
            Audience = "rbac-audience",
            SigningKey = SigningKey,
            ExpirationInMinutes = expirationInMinutes
        };

        return new TokenService(
            Options.Create(jwtOptions),
            Options.Create(new PermissionResolutionOptions { Source = source }));
    }

    private static AppUser User() => new()
    {
        Id = "user-1",
        Email = "user@rbac.dev",
        PasswordHash = "not-a-real-hash",
        FirstName = "Unit",
        LastName = "Test",
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static string Jti(string token) => ReadPayload(token).GetProperty("jti").GetString()!;

    /// <summary>Decodes the JWT payload exactly as it goes over the wire - no claim mapping involved.</summary>
    private static JsonElement ReadPayload(string token)
    {
        string payload = token.Split('.')[1];
        payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');

        byte[] bytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));

        return JsonDocument.Parse(Encoding.UTF8.GetString(bytes)).RootElement.Clone();
    }

    private static string[] PermissionClaims(JsonElement payload)
        => [.. ValuesOf(payload, CustomClaimTypes.Permission)];

    private static string[] Roles(JsonElement payload)
        => [.. ValuesOf(payload, "role").Concat(ValuesOf(payload, ClaimTypes.Role)).Distinct()];

    /// <summary>
    /// A JWT collapses repeated claims of the same type into one JSON array, so a claim can be either a
    /// single string or an array of strings.
    /// </summary>
    private static IEnumerable<string> ValuesOf(JsonElement payload, string claimName)
        => payload.EnumerateObject()
            .Where(property => property.Name == claimName)
            .SelectMany(property => property.Value.ValueKind is JsonValueKind.Array
                ? property.Value.EnumerateArray().Select(item => item.GetString()!)
                : [property.Value.GetString()!]);

    private static Task<TokenValidationResult> ValidateAsync(string token, string signingKey)
        => new JsonWebTokenHandler().ValidateTokenAsync(
            token,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "rbac-issuer",
                ValidateAudience = true,
                ValidAudience = "rbac-audience",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                ValidateLifetime = false
            });
}
