using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Rbac.Api.Data.Entities;

namespace Rbac.Api.Data;

public sealed class RbacDbContext(DbContextOptions<RbacDbContext> options) : DbContext(options)
{
    /// <summary>
    /// SQLite cannot ORDER BY a DateTimeOffset, so timestamps are stored as UTC DateTime values.
    /// The domain types stay DateTimeOffset, which is what the rest of the app works with.
    /// </summary>
    private static readonly ValueConverter<DateTimeOffset, DateTime> UtcDateTimeConverter = new(
        value => value.UtcDateTime,
        value => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)));

    public DbSet<AppUser> Users => Set<AppUser>();

    public DbSet<Role> Roles => Set<Role>();

    public DbSet<Permission> Permissions => Set<Permission>();

    public DbSet<UserRole> UserRoles => Set<UserRole>();

    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();

    public DbSet<Order> Orders => Set<Order>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AppUser>(builder =>
        {
            builder.HasKey(user => user.Id);
            builder.HasIndex(user => user.Email).IsUnique();
            builder.Property(user => user.Email).UseCollation("NOCASE");
            builder.Property(user => user.CreatedAt).HasConversion(UtcDateTimeConverter);
        });

        modelBuilder.Entity<Role>(builder =>
        {
            builder.HasKey(role => role.Id);
            builder.HasIndex(role => role.Name).IsUnique();
            builder.Property(role => role.Name).UseCollation("NOCASE");
        });

        modelBuilder.Entity<Permission>(builder =>
        {
            builder.HasKey(permission => permission.Id);
            builder.HasIndex(permission => permission.Name).IsUnique();
            builder.Property(permission => permission.Name).UseCollation("NOCASE");
        });

        modelBuilder.Entity<UserRole>(builder =>
        {
            builder.HasKey(userRole => new { userRole.UserId, userRole.RoleId });

            builder.HasOne(userRole => userRole.User)
                .WithMany(user => user.UserRoles)
                .HasForeignKey(userRole => userRole.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(userRole => userRole.Role)
                .WithMany(role => role.UserRoles)
                .HasForeignKey(userRole => userRole.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RolePermission>(builder =>
        {
            builder.HasKey(rolePermission => new { rolePermission.RoleId, rolePermission.PermissionId });

            builder.HasOne(rolePermission => rolePermission.Role)
                .WithMany(role => role.RolePermissions)
                .HasForeignKey(rolePermission => rolePermission.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(rolePermission => rolePermission.Permission)
                .WithMany(permission => permission.RolePermissions)
                .HasForeignKey(rolePermission => rolePermission.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserPermission>(builder =>
        {
            builder.HasKey(userPermission => new { userPermission.UserId, userPermission.PermissionId });

            builder.HasOne(userPermission => userPermission.User)
                .WithMany(user => user.UserPermissions)
                .HasForeignKey(userPermission => userPermission.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(userPermission => userPermission.Permission)
                .WithMany(permission => permission.UserPermissions)
                .HasForeignKey(userPermission => userPermission.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Order>(builder =>
        {
            builder.HasKey(order => order.Id);
            builder.Property(order => order.Status).HasConversion<string>().HasMaxLength(20);
            builder.Property(order => order.CreatedAt).HasConversion(UtcDateTimeConverter);
            builder.Property(order => order.CancelledAt).HasConversion(UtcDateTimeConverter);
        });
    }
}
