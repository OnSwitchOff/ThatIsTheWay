using AuthService.Data;
using AuthService.Exceptions;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthService.Tests;

public class LockoutTests
{
    private AuthDbContext GetDbContext()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        return new AuthDbContext(options);
    }

    private LockoutSettings GetTestLockoutSettings() => new LockoutSettings
    {
        FailedAttemptsThreshold = 4,
        LockoutMinutes = 1,
        TrustedIps = new List<string>(),
        UserFailedAttemptsThreshold = 3,
        UserLockoutMinutes = 1
    };

    [Fact]
    public async Task UserIsLockedOutAfterFailedAttempts()
    {
        // Arrange
        var dbContext = GetDbContext();
        var lockoutSettings = GetTestLockoutSettings();
        var options = Options.Create(lockoutSettings);

        // Add a test user
        var user = new User
        {
            Username = "testuser",
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("correctpassword")
        };
        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();

        // Use a fake GeoIpService (or mock)
        var geoService = new FakeGeoIpService();
        var service = new Services.AuthService(dbContext, null, options, geoService);

        // Act: Fail to login 3 times (user threshold) - should lock user
        for (int i = 0; i < lockoutSettings.UserFailedAttemptsThreshold; i++)
        {
            await Assert.ThrowsAsync<System.Security.Authentication.AuthenticationException>(async () =>
                await service.Authenticate("testuser", "wrongpassword", "1.2.3.4"));
        }
        // 4th attempt should throw UserLockedException (not IPLockedException)
        var ex = await Assert.ThrowsAsync<UserLockedException>(async () =>
            await service.Authenticate("testuser", "wrongpassword", "1.2.3.4"));
        Assert.Contains("locked", ex.Message);
    }

    // Add more tests for IP lockout, trusted IPs, etc.

    // Simple fake GeoIpService (replace with Moq if you prefer)
    public class FakeGeoIpService : AuthService.Services.IGeoIpService
    {
        public Task<(string Country, string Region)> GetInfo(string ip) => Task.FromResult(("TestCountry", "TestRegion"));
    }
}
