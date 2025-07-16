using Microsoft.EntityFrameworkCore;
using AuthService.Models;

namespace AuthService.Data
{ 
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        public DbSet<User> Users => Set<User>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>()
                .Property(u => u.Role)
                .HasConversion<string>();

            // Optionally, seed an admin user (with a known password hash)
            var adminId = Guid.NewGuid();
            modelBuilder.Entity<User>().HasData(new User
            {
                Id = adminId,
                Email = "admin@example.com",
                Username = "admin",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin"),
                Role = Role.Admin,
                FullName = "Administrator",
                CreatedAt = DateTime.UtcNow
            });

            base.OnModelCreating(modelBuilder);
        }
    }

}
