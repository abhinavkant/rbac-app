using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Rbac.Api.Authorization;

namespace Rbac.Api.Tests.Unit;

public sealed class PermissionClaimsTransformationTests : IDisposable
{
    private readonly ServiceProvider _services = CreateServices();

    [Fact]
    public async Task Resolved_permissions_are_added_as_claims()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead, Permissions.OrdersRead);

        ClaimsPrincipal principal = await CreateTransformation(permissionService).TransformAsync(Subject("user-1"));

        Assert.Equal(
            [Permissions.OrdersRead, Permissions.UsersRead],
            principal.GetPermissions().OrderBy(permission => permission, StringComparer.Ordinal));
    }

    [Fact]
    public async Task Running_twice_does_not_duplicate_the_claims()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead);

        ClaimsPrincipal principal = Subject("user-1");
        PermissionClaimsTransformation transformation = CreateTransformation(permissionService);

        await transformation.TransformAsync(principal);
        ClaimsPrincipal again = await transformation.TransformAsync(principal);

        Assert.Single(again.GetPermissions());
        Assert.Equal(1, permissionService.CallCount);
    }

    [Fact]
    public async Task Permissions_are_cached_between_transformations()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead);

        // Two different principals for the same user, as two requests would produce.
        await CreateTransformation(permissionService).TransformAsync(Subject("user-1"));
        ClaimsPrincipal second = await CreateTransformation(permissionService).TransformAsync(Subject("user-1"));

        Assert.Equal([Permissions.UsersRead], second.GetPermissions());
        Assert.Equal(1, permissionService.CallCount);
    }

    [Fact]
    public async Task DisableCache_always_goes_back_to_the_database()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead);

        // Two different principals for the same user, as two requests would produce.
        await CreateTransformation(permissionService, disableCache: true).TransformAsync(Subject("user-1"));
        ClaimsPrincipal second = await CreateTransformation(permissionService, disableCache: true).TransformAsync(Subject("user-1"));

        Assert.Equal<IEnumerable<string>>([Permissions.UsersRead], second.GetPermissions());
        Assert.Equal(2, permissionService.CallCount);
    }

    [Fact]
    public async Task A_user_without_permissions_still_gets_a_cache_entry()
    {
        // Otherwise a permission-less user would hit the database on every single request.
        var permissionService = new FakePermissionService();

        await CreateTransformation(permissionService).TransformAsync(Subject("user-1"));
        ClaimsPrincipal second = await CreateTransformation(permissionService).TransformAsync(Subject("user-1"));

        Assert.Empty(second.GetPermissions());
        Assert.Equal(1, permissionService.CallCount);
    }

    [Fact]
    public async Task Different_users_do_not_share_a_cache_entry()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead);
        PermissionClaimsTransformation transformation = CreateTransformation(permissionService);

        ClaimsPrincipal first = await transformation.TransformAsync(Subject("user-1"));
        ClaimsPrincipal second = await transformation.TransformAsync(Subject("user-2"));

        Assert.Equal([Permissions.UsersRead], first.GetPermissions());
        Assert.Equal([Permissions.UsersRead], second.GetPermissions());
        Assert.Equal(2, permissionService.CallCount);
        Assert.Equal("rbac:permissions:user-1", PermissionCacheKeys.ForUser("user-1"));
    }

    [Fact]
    public async Task Anonymous_principals_are_left_alone()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead);

        ClaimsPrincipal principal = await CreateTransformation(permissionService).TransformAsync(new ClaimsPrincipal());

        Assert.Empty(principal.GetPermissions());
        Assert.Equal(0, permissionService.CallCount);
    }

    [Fact]
    public async Task An_authenticated_token_without_a_subject_is_left_alone()
    {
        var permissionService = new FakePermissionService(Permissions.UsersRead);

        var identity = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Email, "nobody@rbac.dev")], authenticationType: "Test");

        ClaimsPrincipal principal = await CreateTransformation(permissionService).TransformAsync(new ClaimsPrincipal(identity));

        Assert.Empty(principal.GetPermissions());
        Assert.Equal(0, permissionService.CallCount);
    }

    public void Dispose()
    {
        _services.Dispose();

        GC.SuppressFinalize(this);
    }

    private PermissionClaimsTransformation CreateTransformation(
        IPermissionService permissionService,
        bool disableCache = false)
        => new(
            permissionService,
            _services.GetRequiredService<HybridCache>(),
            Options.Create(new PermissionResolutionOptions
            {
                Source = PermissionSource.Server,
                DisableCache = disableCache
            }),
            NullLogger<PermissionClaimsTransformation>.Instance);

    private static ServiceProvider CreateServices()
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddDistributedMemoryCache();

        services.AddHybridCache();

        return services.BuildServiceProvider();
    }

    private static ClaimsPrincipal Subject(string userId)
        => new(new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, userId)], authenticationType: "Test"));

    private sealed class FakePermissionService(params string[] permissions) : IPermissionService
    {
        public int CallCount { get; private set; }

        public Task<string[]> GetPermissionsAsync(string userId, CancellationToken cancellationToken = default)
        {
            CallCount++;

            return Task.FromResult(permissions);
        }

        public Task<string[]> GetRolesAsync(string userId, CancellationToken cancellationToken = default)
            => Task.FromResult(Array.Empty<string>());
    }
}
