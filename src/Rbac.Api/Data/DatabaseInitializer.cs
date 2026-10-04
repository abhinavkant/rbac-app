using Microsoft.EntityFrameworkCore;

namespace Rbac.Api.Data;

/// <summary>
/// Creates the SQLite database and seeds the RBAC data on startup.
/// <para>
/// A sample app uses <c>EnsureCreated</c> so it runs with zero setup; a real project should use
/// EF Core migrations instead (<c>dotnet ef migrations add Initial</c>).
/// </para>
/// </summary>
public sealed class DatabaseInitializer(
    IServiceProvider serviceProvider,
    ILogger<DatabaseInitializer> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using IServiceScope scope = serviceProvider.CreateScope();

        var dbContext = scope.ServiceProvider.GetRequiredService<RbacDbContext>();
        var seeder = scope.ServiceProvider.GetRequiredService<RbacSeeder>();

        // SQLite, single file, so this works out of the box with nothing else installed.
        await dbContext.Database.EnsureCreatedAsync(cancellationToken);
        await seeder.SeedAsync(cancellationToken);

        logger.LogInformation("Database ready ({Provider}).", dbContext.Database.ProviderName);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
