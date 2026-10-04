using Microsoft.EntityFrameworkCore;
using Rbac.Api.Data;

namespace Rbac.Api.Authorization;

/// <summary>
/// The list of valid role and permission names, used to reject typos before they become 500s.
/// Permissions are defined in code (<see cref="Permissions.All"/>); roles live in the database.
/// </summary>
public interface IAuthorizationCatalog
{
    /// <summary>Every permission name the application accepts.</summary>
    IReadOnlyList<string> KnownPermissions { get; }

    /// <summary>Every role name currently defined in the database.</summary>
    Task<IReadOnlyList<string>> GetKnownRolesAsync(CancellationToken cancellationToken = default);

    /// <summary>The subset of <paramref name="roleNames"/> that no role matches.</summary>
    Task<IReadOnlyList<string>> FindUnknownRolesAsync(IEnumerable<string>? roleNames, CancellationToken cancellationToken = default);

    /// <summary>The subset of <paramref name="permissionNames"/> that no permission matches.</summary>
    IReadOnlyList<string> FindUnknownPermissions(IEnumerable<string>? permissionNames);
}

public sealed class DatabaseAuthorizationCatalog(RbacDbContext dbContext) : IAuthorizationCatalog
{
    public IReadOnlyList<string> KnownPermissions => Permissions.All;

    public async Task<IReadOnlyList<string>> GetKnownRolesAsync(CancellationToken cancellationToken = default)
        => await dbContext.Roles
            .AsNoTracking()
            .OrderBy(role => role.Name)
            .Select(role => role.Name)
            .ToArrayAsync(cancellationToken);

    public async Task<IReadOnlyList<string>> FindUnknownRolesAsync(IEnumerable<string>? roleNames, CancellationToken cancellationToken = default)
        => FindUnknown(roleNames, await GetKnownRolesAsync(cancellationToken));

    public IReadOnlyList<string> FindUnknownPermissions(IEnumerable<string>? permissionNames)
        => FindUnknown(permissionNames, KnownPermissions);

    private static IReadOnlyList<string> FindUnknown(IEnumerable<string>? names, IReadOnlyCollection<string> known)
    {
        if (names is null)
        {
            return [];
        }

        HashSet<string> knownNames = new(known, StringComparer.OrdinalIgnoreCase);

        // The trimmed name is what gets reported, so a caller sending "  Wizard  " and "Wizard" gets one
        // clear error back instead of the same typo twice. The Where below has already removed the
        // null and whitespace cases, which is what lets the result stay a string list.
        return
        [
            .. names
                .Select(name => name?.Trim())
                .OfType<string>()
                .Where(name => name.Length > 0 && !knownNames.Contains(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
        ];
    }
}
