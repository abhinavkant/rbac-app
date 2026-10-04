namespace Rbac.Api.Authorization;

/// <summary>
/// The catalog of every permission the application knows about.
/// <para>
/// Permissions - not role names - are what the code checks. Roles are just bundles of these
/// strings, which means a role can be created, changed or removed without touching endpoint code.
/// </para>
/// </summary>
public static class Permissions
{
    // Users resource
    public const string UsersRead = "users:read";
    public const string UsersCreate = "users:create";
    public const string UsersUpdate = "users:update";
    public const string UsersDelete = "users:delete";
    public const string UsersAssignRoles = "users:assign-roles";
    public const string UsersGrantPermissions = "users:grant-permissions";

    // Orders resource
    public const string OrdersRead = "orders:read";
    public const string OrdersCreate = "orders:create";
    public const string OrdersCancel = "orders:cancel";

    // Reports resource
    public const string ReportsRead = "reports:read";
    public const string ReportsExport = "reports:export";

    /// <summary>Every permission in the catalog, used by tests and the seeder.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        UsersRead,
        UsersCreate,
        UsersUpdate,
        UsersDelete,
        UsersAssignRoles,
        UsersGrantPermissions,
        OrdersRead,
        OrdersCreate,
        OrdersCancel,
        ReportsRead,
        ReportsExport
    ];

    /// <summary>Resource part of a permission name ("users" for "users:read").</summary>
    public static string GetResource(string permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        int separator = permission.IndexOf(':');
        return separator < 0 ? permission : permission[..separator];
    }

    /// <summary>Action part of a permission name ("read" for "users:read").</summary>
    public static string GetAction(string permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        int separator = permission.IndexOf(':');
        return separator < 0 || separator == permission.Length - 1 ? string.Empty : permission[(separator + 1)..];
    }
}
