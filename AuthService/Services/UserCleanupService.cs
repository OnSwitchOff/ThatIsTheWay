using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Services
{
    /// <summary>
    /// Background service that periodically removes expired or old user accounts from the database.
    /// </summary>
    public class UserCleanupService(IServiceScopeFactory scopeFactory) : BackgroundService
    {
        /// <summary>
        /// Factory for creating service scopes.
        /// </summary>
        private readonly IServiceScopeFactory _scopeFactory = scopeFactory;

        /// <summary>
        /// The interval between cleanup operations.
        /// </summary>
        private readonly TimeSpan _interval = TimeSpan.FromHours(1); // Run every hour

        /// <summary>
        /// Executes the background cleanup task.
        /// Periodically deletes users whose confirmation token has expired and are not confirmed,
        /// as well as users older than 90 days.
        /// </summary>
        /// <param name="stoppingToken">Token to signal cancellation of the background task.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                using var scope = _scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                var now = DateTime.UtcNow;

                // Delete users whose confirmation token expired and are not confirmed
                var expiredUnconfirmed = await dbContext.Users
                    .Where(u => !u.IsConfirmed && u.EmailConfirmationTokenExpiry != null && u.EmailConfirmationTokenExpiry < now)
                    .ToListAsync(stoppingToken);

                // Existing logic for users older than 90 days
                var oldUsers = await dbContext.Users
                    .Where(u => u.CreatedAt < now.AddDays(-90))
                    .ToListAsync(stoppingToken);

                var toDelete = expiredUnconfirmed.Concat(oldUsers).Distinct().ToList();

                if (toDelete.Count > 0)
                {
                    dbContext.Users.RemoveRange(toDelete);
                    await dbContext.SaveChangesAsync(stoppingToken);
                }

                await Task.Delay(_interval, stoppingToken);
            }
        }
    }
}