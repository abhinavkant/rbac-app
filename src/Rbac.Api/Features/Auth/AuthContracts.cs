namespace Rbac.Api.Features.Auth;

public sealed record LoginRequest(string? Email, string? Password);

public sealed record LoginResponse(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAt,
    string[] Roles,
    string[] Permissions,
    string PermissionSource);

/// <summary>Shows what the current token turned into: identity, roles and effective permissions.</summary>
public sealed record MeResponse(
    string Id,
    string Email,
    string FullName,
    string[] Roles,
    string[] Permissions,
    string PermissionSource);
