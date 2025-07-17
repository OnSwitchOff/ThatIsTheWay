using Microsoft.EntityFrameworkCore;
using AuthService.Models;

namespace AuthService.Data
{ 
  /// <summary>
    /// Represents the Entity Framework database context for authentication.
    /// </summary>
    public class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
    {
        /// <summary>
        /// Gets the DbSet for users.
        /// </summary>
        public DbSet<User> Users => Set<User>();
        /// <summary>
        /// Gets the DbSet for login attempts.
        /// </summary>
        public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();

        /// <summary>
        /// Configures the entity mappings and seeds initial data for the authentication database context.
        /// </summary>
        /// <param name="modelBuilder">The builder used to construct the model for the context.</param>
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

                CreatedAt = DateTime.UtcNow,

                MustChangePassword = true

            });



            base.OnModelCreating(modelBuilder);

        }
    }

}
