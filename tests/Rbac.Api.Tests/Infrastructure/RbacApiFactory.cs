using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Rbac.Api.Authorization;
using Rbac.Api.Data;

namespace Rbac.Api.Tests.Infrastructure;

/// <summary>
/// Boots the real app (the same Program.cs) against a throwaway SQLite file, so the seeded RBAC graph
/// is genuine and every test class gets its own database. The concrete subclasses below pick the
/// permission resolution mode, because xUnit class fixtures must expose a single public constructor.
/// </summary>
public class RbacApiFactory : WebApplicationFactory<Program>
{
    private readonly PermissionSource _permissionSource;
    private readonly string _databasePath = Path.Combine(Path.GetTempPath(), $"rbac-tests-{Guid.NewGuid():N}.db");

    protected RbacApiFactory(PermissionSource permissionSource) => _permissionSource = permissionSource;

    public async Task<string> LoginAsync(HttpClient client, SeedUser user)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("/auth/login", new { email = user.Email, password = user.Password });

        response.EnsureSuccessStatusCode();

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();

        return login!.AccessToken;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        // These land on top of appsettings.json, so each factory gets an isolated database and the
        // permission resolution mode under test.
        builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:RbacDb"] = $"Data Source={_databasePath}",
                ["Authorization:PermissionSource"] = _permissionSource.ToString(),
                ["Jwt:SigningKey"] = "test-only-signing-key-0123456789-abcdefghijklmnop"
            }));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        foreach (string path in new[] { _databasePath, $"{_databasePath}-shm", $"{_databasePath}-wal" })
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                // A leftover file in the temp folder is not worth failing a test over.
            }
        }
    }

    private sealed record LoginResponse(string AccessToken);
}

/// <summary>Permissions are written into the access token (the default).</summary>
public sealed class TokenSourceApiFactory : RbacApiFactory
{
    public TokenSourceApiFactory()
        : base(PermissionSource.Token)
    {
    }
}

/// <summary>Permissions are resolved per request by the claims transformation.</summary>
public sealed class ServerSourceApiFactory : RbacApiFactory
{
    public ServerSourceApiFactory()
        : base(PermissionSource.Server)
    {
    }
}
