using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;
using Rbac.Api.Security;

namespace Rbac.Api.Features.Auth;

/// <summary>
/// Login and identity. No action here names a permission policy: obtaining a token obviously cannot
/// require one, and "who am I" is answered to any authenticated caller.
/// </summary>
[ApiController]
[Route("auth")]
[Tags("Authentication")]
public sealed class AuthController(
    RbacDbContext dbContext,
    IPasswordHasher<AppUser> passwordHasher,
    IPermissionService permissionService,
    ITokenService tokenService,
    IOptions<PermissionResolutionOptions> permissionOptions) : RbacControllerBase
{
    /// <summary>Exchanges credentials for an access token carrying roles and permissions.</summary>
    [HttpPost("login")]
    [AllowAnonymous]
    [EndpointSummary("Exchanges credentials for an access token carrying roles and permissions.")]
    [ProducesResponseType<LoginResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<LoginResponse>> LoginAsync(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["credentials"] = ["Email and password are required."]
            });
        }

        AppUser? user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.Email == request.Email.Trim(), cancellationToken);

        // Same answer for "no such user" and "wrong password" so the endpoint cannot be used to
        // enumerate accounts.
        if (user is null
            || !user.IsActive
            || passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password) is PasswordVerificationResult.Failed)
        {
            return Problem(
                title: "Invalid credentials",
                detail: "The email address or password is incorrect.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        string[] roles = await permissionService.GetRolesAsync(user.Id, cancellationToken);
        string[] permissions = await permissionService.GetPermissionsAsync(user.Id, cancellationToken);

        AccessToken accessToken = tokenService.CreateAccessToken(user, roles, permissions);

        return Ok(new LoginResponse(
            accessToken.Token,
            "Bearer",
            accessToken.ExpiresAt,
            roles,
            permissions,
            permissionOptions.Value.Source.ToString()));
    }

    /// <summary>Shows what the current token turned into: identity, roles and effective permissions.</summary>
    [HttpGet("me")]
    [Authorize]
    [EndpointSummary("Returns the caller's identity, roles and effective permissions.")]
    [ProducesResponseType<MeResponse>(StatusCodes.Status200OK)]
    public ActionResult<MeResponse> Me()
    {
        string userId = User.FindFirstValue(JwtRegisteredClaimNames.Sub)!;

        AppUser? user = dbContext.Users
            .AsNoTracking()
            .FirstOrDefault(u => u.Id == userId);

        if (user is null)
        {
            return Problem(
                title: "User not found",
                detail: "The token is valid but the user no longer exists.",
                statusCode: StatusCodes.Status404NotFound);
        }

        // Read the permissions off the principal: they came from the token in Token mode and from
        // the claims transformation in Server mode. Action code cannot tell the difference.
        return Ok(new MeResponse(
            user.Id,
            user.Email,
            $"{user.FirstName} {user.LastName}".Trim(),
            [.. User.FindAll(ClaimTypes.Role).Select(claim => claim.Value)],
            [.. User.GetPermissions()],
            permissionOptions.Value.Source.ToString()));
    }
}
