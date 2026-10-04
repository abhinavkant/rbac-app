using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Rbac.Api.Authorization;
using Rbac.Api.Data.Entities;

// Both Microsoft.IdentityModel.JsonWebTokens and System.IdentityModel.Tokens.Jwt define this type.
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Rbac.Api.Security;

public interface ITokenService
{
    AccessToken CreateAccessToken(AppUser user, string[] roles, string[] permissions);
}

public sealed record AccessToken(string Token, DateTimeOffset ExpiresAt, int ExpiresInSeconds);

/// <summary>
/// Issues the access token. Permissions become claims only when the app is configured to use
/// <see cref="PermissionSource.Token"/>; in <see cref="PermissionSource.Server"/> mode the token stays
/// small and the permissions are resolved per request by the claims transformation.
/// </summary>
public sealed class TokenService(
    IOptions<JwtOptions> jwtOptions,
    IOptions<PermissionResolutionOptions> permissionOptions) : ITokenService
{
    public AccessToken CreateAccessToken(AppUser user, string[] roles, string[] permissions)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(permissions);

        JwtOptions options = jwtOptions.Value;

        var claims = new List<Claim>
        {
            // "sub" is the user id, and it is what server-side permission resolution keys on.
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Roles travel with the token for auditing and UI decisions. No endpoint authorizes on them.
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        if (permissionOptions.Value.Source is PermissionSource.Token)
        {
            claims.AddRange(permissions.Select(permission => new Claim(CustomClaimTypes.Permission, permission)));
        }

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.SigningKey));
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(options.ExpirationInMinutes);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = options.Issuer,
            Audience = options.Audience,
            IssuedAt = DateTimeOffset.UtcNow.UtcDateTime,
            NotBefore = DateTimeOffset.UtcNow.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
        };

        var tokenHandler = new JsonWebTokenHandler();

        return new AccessToken(tokenHandler.CreateToken(tokenDescriptor), expiresAt, (int)TimeSpan.FromMinutes(options.ExpirationInMinutes).TotalSeconds);
    }
}
