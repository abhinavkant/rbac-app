using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;

namespace Rbac.Api.Tests.Infrastructure;

/// <summary>
/// A real SQLite database held in memory, for the tests that exercise the data layer on its own.
/// <para>
/// SQLite is the same provider the app uses, so a query that the tests accept is a query the app can
/// translate. The EF in-memory provider would happily accept LINQ that SQLite rejects, which is
/// exactly the class of bug these tests exist to catch.
/// </para>
/// </summary>
public sealed class SqliteRbacDb : IAsyncDisposable
{
    private readonly SqliteConnection _connection;

    private SqliteRbacDb(SqliteConnection connection, RbacDbContext dbContext)
    {
        _connection = connection;
        DbContext = dbContext;
    }

    public RbacDbContext DbContext { get; }

    /// <summary>Creates an empty schema, or a seeded one when <paramref name="seed"/> is true.</summary>
    public static async Task<SqliteRbacDb> CreateAsync(bool seed = false)
    {
        // A shared in-memory database only lives as long as the connection is open.
        var connection = new SqliteConnection("Filename=:memory:");
        await connection.OpenAsync();

        DbContextOptions<RbacDbContext> options = new DbContextOptionsBuilder<RbacDbContext>()
            .UseSqlite(connection)
            .Options;

        var dbContext = new RbacDbContext(options);
        await dbContext.Database.EnsureCreatedAsync();

        var database = new SqliteRbacDb(connection, dbContext);

        if (seed)
        {
            await database.SeedAsync();
        }

        return database;
    }

    /// <summary>Runs the production seeder against this database.</summary>
    public async Task SeedAsync()
    {
        var seeder = new RbacSeeder(DbContext, new PasswordHasher<AppUser>(), NullLogger<RbacSeeder>.Instance);

        await seeder.SeedAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await DbContext.DisposeAsync();
        await _connection.DisposeAsync();
    }
}
