namespace Rbac.Api.Authorization;

/// <summary>
/// Claim types used by this application. The permission claim is the whole point of the RBAC
/// sample: it is what <see cref="PermissionAuthorizationRequirement"/> looks for.
/// </summary>
public static class CustomClaimTypes
{
    public const string Permission = "permission";
}
