using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Rbac.Api.Security;

namespace Rbac.Api.Configuration;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddRbacAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        // The bearer handler is configured from the bound options rather than from a second read of
        // the configuration, so the key that validates tokens is always the key that signed them -
        // including when a test overrides Jwt:* settings.
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtOptions>>((bearer, jwtOptions) => ConfigureBearer(bearer, jwtOptions.Value));

        return services;
    }

    private static void ConfigureBearer(JwtBearerOptions bearer, JwtOptions jwt)
    {
        // Keep claim types exactly as issued: "sub" stays "sub" instead of being remapped to
        // ClaimTypes.NameIdentifier, which makes tokens readable and predictable.
        bearer.MapInboundClaims = false;

        bearer.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = JwtRegisteredClaimNames.Email,
            RoleClaimType = ClaimTypes.Role
        };

        // Turn the default empty 401/403 responses into problem documents.
        bearer.Events = new RbacJwtBearerEvents();
    }
}
