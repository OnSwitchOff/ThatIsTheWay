using AuthService.Data;
using AuthService.Dtos;
using AuthService.Exceptions;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
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

        public AuthService(AuthDbContext dbContext, string jwtKey, IOptions<LockoutSettings> lockoutOptions, IGeoIpService geoIpService)
        {
            _dbContext = dbContext;
            _jwtKey = jwtKey;
            _lockoutSettings = lockoutOptions.Value;
            _geoIpService = geoIpService;
        }

        public async Task<bool> RegisterUser(string email, string password)
        {
            if (await _dbContext.Users.AnyAsync(u => u.Username == email))
                return false;

            var user = new User
            {
                Email = email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(password)
            };

            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();
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
    }

}
