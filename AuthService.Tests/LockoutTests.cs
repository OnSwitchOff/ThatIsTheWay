using AuthService.Data;
using AuthService.Exceptions;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AuthService.Tests;

public class LockoutTests
{
    private static AuthDbContext GetDbContext()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        return new AuthDbContext(options);
    }

    private static LockoutSettings GetTestLockoutSettings() => new()
    {
        FailedAttemptsThreshold = 4,
        LockoutMinutes = 1,
        TrustedIps = { },
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
        var emailService = new FakeEmailService();
        var jwtKey = "test_jwt_key_123"; // Use any test key string
        var memoryCache = new MemoryCache(new MemoryCacheOptions()); // Add this line
        var service = new Services.AuthService(dbContext, jwtKey, options, geoService, emailService, memoryCache); // Pass memoryCache

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

    public class FakeEmailService : AuthService.Services.IEmailService
    {
        public Task SendEmailAsync(string to, string subject, string body) => Task.CompletedTask;
    }
}
