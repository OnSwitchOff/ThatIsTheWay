using AuthService.Dtos;
using AuthService.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Authentication;
using System.Security.Claims;

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
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var response = await _authService.Authenticate(request.Username, request.Password, HttpContext.Connection.RemoteIpAddress!.ToString());
                return Ok(response);
            }
            catch (IpLockedException ex)
            {
                return StatusCode(429, new { error = "ip_locked", message = ex.Message, retry_after_minutes = ex.RetryAfterMinutes });
            }
            catch (AuthenticationException ex)
            {
                return Unauthorized(new { error = "authentication_failed", message = ex.Message });
            }
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

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequest request)
        {
            var currentUserId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (currentUserId == null || request.UserId.ToString() != currentUserId)
                return Forbid("You can only change your own password.");

            var result = await _authService.ChangeUserPassword(request.UserId, request.NewPassword);
            if (!result)
                return NotFound("User not found or password change failed");

            return Ok("Password updated");
        }

        [Authorize]
        [HttpDelete("delete/{id:guid}")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            var userToDelete = await _authService.GetUserById(id);
            if (userToDelete == null || userToDelete.IsDeleted)
                return NotFound("User not found");

            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var currentUserRole = User.FindFirst(ClaimTypes.Role)?.Value;

            // Only allow if deleting own account, or if current user is Admin or Manager
            if (currentUserId == null ||
                (currentUserId != id.ToString() && currentUserRole != "Admin" && currentUserRole != "Manager"))
            {
                return Forbid("You are not allowed to delete this user.");
            }

            var result = await _authService.SoftDeleteUser(id);
            if (!result)
                return BadRequest("User could not be deleted.");

            return NoContent();
        }

        [Authorize]
        [HttpPost("restore/{id:guid}")]
        public async Task<IActionResult> RestoreUser(Guid id)
        {
            var userToRestore = await _authService.GetUserById(id);
            if (userToRestore == null || !userToRestore.IsDeleted)
                return NotFound("User not found or not deleted.");

            var currentUserId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var currentUserRole = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            // Only allow if restoring own account, or if current user is Admin or Manager
            if (currentUserId == null ||
                (currentUserId != id.ToString() && currentUserRole != "Admin" && currentUserRole != "Manager"))
            {
                return Forbid("You are not allowed to restore this user.");
            }

            var result = await _authService.RestoreUser(id);
            if (!result)
                return BadRequest("User could not be restored.");

            return Ok("User restored successfully.");
        }

        [Authorize(Roles = "Admin,Manager")]
        [HttpPost("confirm/{id:guid}")]
        public async Task<IActionResult> ConfirmUser(Guid id)
        {
            var user = await _authService.GetUserById(id);
            if (user == null)
                return NotFound("User not found.");

            if (user.IsConfirmed)
                return BadRequest("User is already confirmed.");

            var result = await _authService.ConfirmUser(id);
            if (!result)
                return BadRequest("User could not be confirmed.");

            return Ok("User confirmed successfully.");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string token)
        {
            var user = await _authService.GetUserByConfirmationToken(token);
            if (user == null || user.IsConfirmed)
                return BadRequest("Invalid or expired token.");

            var result = await _authService.ConfirmUserByToken(token);
            if (!result)
                return BadRequest("User could not be confirmed.");

            return Ok("Email confirmed successfully.");
        }

        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new { status = "Healthy" });
        }
    }

}
