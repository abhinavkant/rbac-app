namespace Rbac.Api.Authorization;

/// <summary>
/// Policy names for <c>[Authorize(Policy = ...)]</c>.
/// <para>
/// A permission name is itself a policy name: every entry in <see cref="Permissions.All"/> gets a policy
/// registered for it in <see cref="Configuration.AuthorizationExtensions.AddRbacAuthorization"/>, so an
/// action names the constant it needs and nothing has to be repeated in a registration table:
/// <code>[Authorize(Policy = Permissions.UsersRead)]</code>
/// </para>
/// <para>
/// An action that needs several permissions at once needs a policy of its own, and attribute arguments
/// have to be compile-time constants - which is why that name is a <c>const</c> here instead of being
/// composed at the call site.
/// </para>
/// </summary>
public static class PermissionPolicies
{
    /// <summary>
    /// A caller needs <c>reports:read</c> AND <c>reports:export</c>: the combined report action.
    /// </summary>
    public const string ReportsReadAndExport = "reports:read+reports:export";

    /// <summary>
    /// Builds the name of an "all of these permissions" policy. For actions declared outside this project;
    /// an action here uses the named constant above so the name stays checkable by the compiler.
    /// </summary>
    public static string AllOf(string permission, params string[] otherPermissions)
        => string.Join('+', [permission, .. otherPermissions]);
}
