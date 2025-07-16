
using AuthService.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Controllers
{


    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly Services.AuthService _authService;

        public AuthController(Services.AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest request)
        {
            var result = await _authService.RegisterUser(request.Email, request.Password);
            if (!result)
                return BadRequest("User already exists");

            return Ok("User registered successfully");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var loginResponse = await _authService.Authenticate(request.Username, request.Password);
            if (loginResponse == null)
                return Unauthorized("Invalid username or password");

            return Ok(loginResponse);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("change-role")]
        public async Task<IActionResult> ChangeRole(ChangeRoleRequest request)
        {
            var user = await _authService.GetUserById(request.UserId);
            if (user == null)
                return NotFound("User not found");

            var result = await _authService.ChangeUserRole(request.UserId, request.NewRole);
            if (!result)
                return BadRequest("Role change failed");

            return Ok("User role updated");
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequest request)
        {
            var user = await _authService.GetUserById(request.UserId);
            if (user == null)
                return NotFound();

            var result = await _authService.ChangeUserPassword(request.UserId, request.NewPassword);
            if (!result)
                return BadRequest("Password change failed");

            return Ok("Password updated");
        }
    }

}
