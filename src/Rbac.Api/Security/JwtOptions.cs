using System.ComponentModel.DataAnnotations;

namespace Rbac.Api.Security;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    public required string Issuer { get; set; }

    [Required]
    public required string Audience { get; set; }

    /// <summary>HMAC-SHA256 signing key. At least 32 characters (256 bits).</summary>
    [Required]
    [MinLength(32, ErrorMessage = "Jwt:SigningKey must be at least 32 characters long.")]
    public required string SigningKey { get; set; }

    [Range(1, 1440)]
    public int ExpirationInMinutes { get; set; } = 30;
}
