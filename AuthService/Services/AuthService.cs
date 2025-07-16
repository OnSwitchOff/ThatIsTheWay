using AuthService.Data;
using AuthService.Dtos;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;


namespace AuthService.Services
{
    public class AuthService
    {
        private readonly AuthDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public AuthService(AuthDbContext dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
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

        public async Task<LoginResponseDto?> Authenticate(string username, string password, string ip)
        {
            var since = DateTime.UtcNow.AddMinutes(-15);
            var failedCount = await _dbContext.LoginAttempts
                .CountAsync(a => a.IpAddress == ip && !a.IsSuccessful && a.Timestamp > since);

            if (failedCount >= 5)
            {
                var blockedAttempt = new LoginAttempt
                {
                    UserId = null,
                    UsernameAttempted = username,
                    Timestamp = DateTime.UtcNow,
                    IpAddress = ip,
                    IsSuccessful = false,
                    Reason = "ip locked"
                };
                _dbContext.LoginAttempts.Add(blockedAttempt);
                await _dbContext.SaveChangesAsync();
                return null;
            }


            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            var isSuccess = user != null && BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);

            // Log attempt
            var attempt = new LoginAttempt
            {
                UserId = user?.Id,
                UsernameAttempted = username,
                Timestamp = DateTime.UtcNow,
                IpAddress = ip,
                IsSuccessful = isSuccess,
                Reason = isSuccess ? null : (user == null ? "user not found" : "invalid password")
            };

            _dbContext.LoginAttempts.Add(attempt);
            await _dbContext.SaveChangesAsync();

            if (!isSuccess)
                return null;


            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user!.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return new LoginResponseDto
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
