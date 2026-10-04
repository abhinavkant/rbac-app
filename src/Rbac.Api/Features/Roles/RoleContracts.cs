namespace Rbac.Api.Features.Roles;

public sealed record RoleDefinitionResponse(string Name, string[] Permissions);

public sealed record AuthorizationCatalogResponse(string[] Permissions, RoleDefinitionResponse[] Roles);
