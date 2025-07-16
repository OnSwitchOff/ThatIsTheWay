using AuthService.Data;
using AuthService.Dtos;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
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

        public async Task<LoginResponseDto?> Authenticate(string username, string password)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
                return null;

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
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
                UserId = user.Id
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
    }

}
