using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Services
{
    public class UserCleanupService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly TimeSpan _interval = TimeSpan.FromHours(1); // Run every hour

        public UserCleanupService(IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
        }

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

                if (toDelete.Any())
                {
                    dbContext.Users.RemoveRange(toDelete);
                    await dbContext.SaveChangesAsync(stoppingToken);
                }

                await Task.Delay(_interval, stoppingToken);
            }
        }
    }
}