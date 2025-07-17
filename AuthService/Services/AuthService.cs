using AuthService.Data;
using AuthService.Dtos;
using AuthService.Exceptions;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text;


namespace AuthService.Services
{
    public class AuthService
    {
        private readonly AuthDbContext _dbContext;
        private readonly string _jwtKey;
        private readonly LockoutSettings _lockoutSettings;
        private readonly IGeoIpService _geoIpService;
        private readonly IEmailService _emailService;
        private readonly IMemoryCache _cache;

        public AuthService(AuthDbContext dbContext, string jwtKey, IOptions<LockoutSettings> lockoutOptions, IGeoIpService geoIpService, IEmailService emailService, IMemoryCache cache)
        {
            _dbContext = dbContext;
            _jwtKey = jwtKey;
            _lockoutSettings = lockoutOptions.Value;
            _geoIpService = geoIpService;
            _emailService = emailService;
            _cache = cache;
        }

        public async Task<bool> RegisterUser(string email, string password)
        {
            if (await _dbContext.Users.AnyAsync(u => u.Username == email))
                return false;

            var token = Guid.NewGuid().ToString();
            var user = new User
            {
                Email = email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
                EmailConfirmationToken = token,
                EmailConfirmationTokenExpiry = DateTime.UtcNow.AddHours(24)
            };

            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Send confirmation email (pseudo-code, replace with your email service)
            await _emailService.SendEmailAsync(email, "Confirm your account",
                $"Please confirm your account by clicking this link: https://yourdomain.com/api/auth/confirm-email?token={token}");

            return true;
        }

        public async Task<LoginResponse?> Authenticate(string username, string password, string ip)
        {
            // Trusted IPs bypass IP lockout, but not user lockout
            bool isTrustedIp = _lockoutSettings.TrustedIps.Contains(ip);

            var sinceIp = DateTime.UtcNow.AddMinutes(-_lockoutSettings.LockoutMinutes);
            var sinceUser = DateTime.UtcNow.AddMinutes(-_lockoutSettings.UserLockoutMinutes);

            // IP-based lockout (unless trusted IP)
            if (!isTrustedIp)
            {
                var failedCountIp = await _dbContext.LoginAttempts
                    .CountAsync(a => a.IpAddress == ip && !a.IsSuccessful && a.Timestamp > sinceIp);

                if (failedCountIp >= _lockoutSettings.FailedAttemptsThreshold)
                {
                    var geoInfo = await _geoIpService.GetInfo(ip);
                    var blockedAttempt = new LoginAttempt
                    {
                        UserId = null,
                        UsernameAttempted = username,
                        Timestamp = DateTime.UtcNow,
                        IpAddress = ip,
                        IsSuccessful = false,
                        Reason = "ip locked",
                        Country = geoInfo.Country,
                        Region = geoInfo.Region
                    };
                    _dbContext.LoginAttempts.Add(blockedAttempt);
                    await _dbContext.SaveChangesAsync();
                    throw new IpLockedException(_lockoutSettings.LockoutMinutes);
                }
            }

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);// User-based lockout
            if (user != null)
            {
                var failedCountUser = await _dbContext.LoginAttempts
                    .CountAsync(a => a.UserId == user.Id && !a.IsSuccessful && a.Timestamp > sinceUser);

                if (failedCountUser >= _lockoutSettings.UserFailedAttemptsThreshold)
                {
                    var geoInfo = await _geoIpService.GetInfo(ip);
                    var blockedAttempt = new LoginAttempt
                    {
                        UserId = user.Id,
                        UsernameAttempted = username,
                        Timestamp = DateTime.UtcNow,
                        IpAddress = ip,
                        IsSuccessful = false,
                        Reason = "user locked",
                        Country = geoInfo.Country,
                        Region = geoInfo.Region
                    };
                    _dbContext.LoginAttempts.Add(blockedAttempt);
                    await _dbContext.SaveChangesAsync();
                    throw new UserLockedException(_lockoutSettings.UserLockoutMinutes);
                }
            }
            var isSuccess = user != null && BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);

            var geoData = await _geoIpService.GetInfo(ip);

            var attempt = new LoginAttempt
            {
                UserId = user?.Id,
                UsernameAttempted = username,
                Timestamp = DateTime.UtcNow,
                IpAddress = ip,
                IsSuccessful = isSuccess,
                Reason = isSuccess ? null : (user == null ? "user not found" : "invalid password"),
                Country = geoData.Country,
                Region = geoData.Region
            };

            _dbContext.LoginAttempts.Add(attempt);
            await _dbContext.SaveChangesAsync();

            if (!isSuccess)
                throw new AuthenticationException("Invalid username or password.");

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user!.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return new LoginResponse
            {
                Token = jwt,
                Username = user.Username!,
                UserId = user.Id,
                RequiresPasswordChange = user.MustChangePassword,
            };
        }

        public async Task<User?> GetUserById(Guid userId)
        {
            return await _dbContext.Users.FindAsync(userId);
        }

        public async Task<bool> ChangeUserRole(Guid userId, Role newRole)
        {
            if (newRole == Role.Admin)
                return false;            

            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null)
                return false;

            user.Role = newRole;
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ChangeUserPassword(Guid userId, string newPassword)
        {
            var user = await GetUserById(userId);
            if (user == null)
                return false;

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
            user.MustChangePassword = false; // unset flag
            await _dbContext.SaveChangesAsync();

            return true;
        }

        public async Task<bool> SoftDeleteUser(Guid userId)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null || user.IsDeleted)
                return false;

            user.IsDeleted = true;
            user.DateDeleted = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> RestoreUser(Guid userId)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null || !user.IsDeleted)
                return false;

            user.IsDeleted = false;
            user.DateDeleted = null;
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ConfirmUser(Guid userId)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null || user.IsConfirmed)
                return false;

            user.IsConfirmed = true;
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<User?> GetUserByConfirmationToken(string token)
        {
            return await _dbContext.Users.FirstOrDefaultAsync(u =>
                u.EmailConfirmationToken == token &&
                u.EmailConfirmationTokenExpiry > DateTime.UtcNow);
        }

        public async Task<bool> ConfirmUserByToken(string token)
        {
            var user = await GetUserByConfirmationToken(token);
            if (user == null)
                return false;

            user.IsConfirmed = true;
            user.EmailConfirmationToken = null;
            user.EmailConfirmationTokenExpiry = null;
            await _dbContext.SaveChangesAsync();
            return true;
        }

        // Example: Cache user role lookup
        public async Task<Role?> GetUserRole(Guid userId)
        {
            string cacheKey = $"user_role_{userId}";
            if (_cache.TryGetValue<Role>(cacheKey, out var cachedRole))
                return cachedRole;

            var user = await _dbContext.Users
                .Where(u => u.Id == userId && !u.IsDeleted)
                .Select(u => u.Role)
                .FirstOrDefaultAsync();

            if (user != default)
                _cache.Set(cacheKey, user, TimeSpan.FromMinutes(10));

            return user;
        }
    }

}
