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
    /// <summary>
    /// Provides authentication-related services such as user registration, login, role management, password changes, and user confirmation.
    /// </summary>
    public class AuthService
    (
        AuthDbContext dbContext,
        string jwtKey,
        IOptions<LockoutSettings> lockoutOptions,
        IGeoIpService geoIpService,
        IEmailService emailService,
        IMemoryCache cache)
    {
        private readonly AuthDbContext _dbContext = dbContext;
        private readonly string _jwtKey = jwtKey;
        private readonly LockoutSettings _lockoutSettings = lockoutOptions.Value;
        private readonly IGeoIpService _geoIpService = geoIpService;
        private readonly IEmailService _emailService = emailService;
        private readonly IMemoryCache _cache = cache;

        /// <summary>
        /// Registers a new user with the specified email and password.
        /// Sends a confirmation email to the user with a token for email verification.
        /// Returns true if registration is successful; false if the email is already in use.
        /// </summary>
        /// <param name="email">The email address of the user to register.</param>
        /// <param name="password">The password for the new user.</param>
        /// <returns>True if registration succeeds; otherwise, false.</returns>
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

        /// <summary>
        /// Authenticates a user with the specified username, password, and IP address.
        /// Performs IP-based and user-based lockout checks, logs login attempts, and returns a JWT token if authentication succeeds.
        /// Throws <see cref="IpLockedException"/> if the IP is locked out, <see cref="UserLockedException"/> if the user is locked out,
        /// and <see cref="AuthenticationException"/> if authentication fails.
        /// </summary>
        /// <param name="username">The username of the user attempting to authenticate.</param>
        /// <param name="password">The password of the user.</param>
        /// <param name="ip">The IP address of the request.</param>
        /// <returns>A <see cref="LoginResponse"/> containing authentication details if successful; otherwise, throws an exception.</returns>
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
                    var (country, region) = await _geoIpService.GetInfo(ip);
                    var blockedAttempt = new LoginAttempt
                    {
                        UserId = null,
                        UsernameAttempted = username,
                        Timestamp = DateTime.UtcNow,
                        IpAddress = ip,
                        IsSuccessful = false,
                        Reason = "ip locked",
                        Country = country,
                        Region = region
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
                    var (userCountry, userRegion) = await _geoIpService.GetInfo(ip);
                    var blockedAttempt = new LoginAttempt
                    {
                        UserId = user.Id,
                        UsernameAttempted = username,
                        Timestamp = DateTime.UtcNow,
                        IpAddress = ip,
                        IsSuccessful = false,
                        Reason = "user locked",
                        Country = userCountry,
                        Region = userRegion
                    };
                    _dbContext.LoginAttempts.Add(blockedAttempt);
                    await _dbContext.SaveChangesAsync();
                    throw new UserLockedException(_lockoutSettings.UserLockoutMinutes);
                }
            }
            var isSuccess = user != null && BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);

            var (attemptCountry, attemptRegion) = await _geoIpService.GetInfo(ip);

            var attempt = new LoginAttempt
            {
                UserId = user?.Id,
                UsernameAttempted = username,
                Timestamp = DateTime.UtcNow,
                IpAddress = ip,
                IsSuccessful = isSuccess,
                Reason = isSuccess ? null : (user == null ? "user not found" : "invalid password"),
                Country = attemptCountry,
                Region = attemptRegion
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

        /// <summary>
        /// Retrieves a user by their unique identifier.
        /// </summary>
        /// <param name="userId">The unique identifier of the user.</param>
        /// <returns>The <see cref="User"/> if found; otherwise, null.</returns>
        public async Task<User?> GetUserById(Guid userId)
        {
            return await _dbContext.Users.FindAsync(userId);
        }

        /// <summary>
        /// Changes the role of a user to the specified new role.
        /// Returns false if the new role is Admin or if the user does not exist.
        /// </summary>
        /// <param name="userId">The unique identifier of the user whose role is to be changed.</param>
        /// <param name="newRole">The new role to assign to the user.</param>
        /// <returns>True if the role change succeeds; otherwise, false.</returns>
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

        /// <summary>
        /// Changes the password of the specified user to a new password.
        /// Returns false if the user does not exist.
        /// </summary>
        /// <param name="userId">The unique identifier of the user whose password is to be changed.</param>
        /// <param name="newPassword">The new password to set for the user.</param>
        /// <returns>True if the password change succeeds; otherwise, false.</returns>
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

        /// <summary>
        /// Soft deletes a user by setting the IsDeleted flag and DateDeleted timestamp.
        /// Returns false if the user does not exist or is already deleted.
        /// </summary>
        /// <param name="userId">The unique identifier of the user to soft delete.</param>
        /// <returns>True if the user was successfully soft deleted; otherwise, false.</returns>
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

        /// <summary>
        /// Restores a previously soft-deleted user by unsetting the IsDeleted flag and clearing the DateDeleted timestamp.
        /// Returns false if the user does not exist or is not deleted.
        /// </summary>
        /// <param name="userId">The unique identifier of the user to restore.</param>
        /// <returns>True if the user was successfully restored; otherwise, false.</returns>
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

        /// <summary>
        /// Confirms a user by setting the IsConfirmed flag to true.
        /// Returns false if the user does not exist or is already confirmed.
        /// </summary>
        /// <param name="userId">The unique identifier of the user to confirm.</param>
        /// <returns>True if the user was successfully confirmed; otherwise, false.</returns>
        public async Task<bool> ConfirmUser(Guid userId)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null || user.IsConfirmed)
                return false;

            user.IsConfirmed = true;
            await _dbContext.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Retrieves a user by their email confirmation token if the token is valid and not expired.
        /// </summary>
        /// <param name="token">The email confirmation token to search for.</param>
        /// <returns>The <see cref="User"/> if found and token is valid; otherwise, null.</returns>
        public async Task<User?> GetUserByConfirmationToken(string token)
        {
            return await _dbContext.Users.FirstOrDefaultAsync(u =>
                u.EmailConfirmationToken == token &&
                u.EmailConfirmationTokenExpiry > DateTime.UtcNow);
        }

        /// <summary>
        /// Confirms a user by their email confirmation token.
        /// Sets the user's IsConfirmed flag to true and clears the confirmation token and expiry.
        /// Returns false if the token is invalid or expired, or if the user does not exist.
        /// </summary>
        /// <param name="token">The email confirmation token to validate and confirm the user.</param>
        /// <returns>True if the user was successfully confirmed; otherwise, false.</returns>
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

        /// <summary>
        /// Retrieves the role of a user by their unique identifier.
        /// Returns the user's role if found and not deleted; otherwise, null.
        /// </summary>
        /// <param name="userId">The unique identifier of the user.</param>
        /// <returns>The <see cref="Role"/> of the user if found; otherwise, null.</returns>
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
