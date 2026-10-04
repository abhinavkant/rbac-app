namespace Rbac.Api.Features.Users;

public sealed record UserResponse(
    string Id,
    string Email,
    string FullName,
    bool IsActive,
    string[] Roles,
    string[] DirectPermissions);

public sealed record CreateUserRequest(
    string? Email,
    string? Password,
    string? FirstName,
    string? LastName,
    string[]? Roles,
    string[]? Permissions);

public sealed record UpdateUserRequest(string? FirstName, string? LastName, bool? IsActive);

public sealed record AssignRolesRequest(string[]? Roles);

public sealed record GrantPermissionsRequest(string[]? Permissions, bool Revoke);
