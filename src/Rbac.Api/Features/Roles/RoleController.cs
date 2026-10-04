using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data;

namespace Rbac.Api.Features.Roles;

/// <summary>
/// Exposes the RBAC configuration so you can see it: which permissions exist and which role carries
/// which of them. Requires a valid token, but no specific permission - it reveals nothing sensitive.
/// </summary>
[ApiController]
[Route("roles")]
[Tags("Roles")]
public sealed class RoleController(RbacDbContext dbContext) : RbacControllerBase
{
    /// <summary>Lists every permission and the roles that carry them.</summary>
    [HttpGet]
    [Authorize]
    [EndpointSummary("Lists every permission and the roles that carry them.")]
    [ProducesResponseType<AuthorizationCatalogResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<AuthorizationCatalogResponse>> GetAsync(CancellationToken cancellationToken)
    {
        RoleDefinitionResponse[] roles = await dbContext.Roles
            .AsNoTracking()
            .OrderBy(role => role.Name)
            .Select(role => new RoleDefinitionResponse(
                role.Name,
                role.RolePermissions
                    .Select(rolePermission => rolePermission.Permission.Name)
                    .OrderBy(name => name)
                    .ToArray()))
            .ToArrayAsync(cancellationToken);

        return Ok(new AuthorizationCatalogResponse([.. Permissions.All], roles));
    }
}
