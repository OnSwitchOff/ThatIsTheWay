
using AuthService.Dtos;
using Microsoft.AspNetCore.Mvc;

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
    }

}
