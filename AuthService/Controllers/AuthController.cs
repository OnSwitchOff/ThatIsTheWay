using AuthService.Dtos;
using AuthService.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Authentication;
using System.Security.Claims;

namespace AuthService.Controllers
{

    /// <summary>
    /// Controller for authentication and user management operations.
    /// </summary>
    [ApiController]
    public class AuthController(Services.AuthService authService) : ControllerBase
    {
        private readonly Services.AuthService _authService = authService;

        /// <summary>
        /// Registers a new user.
        /// </summary>
        /// <param name="request">Registration details.</param>
        /// <returns>Result of registration.</returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterUser(request.Email, request.Password);
            if (!result)
                return BadRequest("User already exists");

            return Ok("User registered successfully");
        }

        /// <summary>
        /// Authenticates a user and returns a JWT token if successful.
        /// </summary>
        /// <param name="request">Login details including username and password.</param>
        /// <returns>Login response containing token and user information, or error details.</returns>
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

        /// <summary>
        /// Changes the role of a specified user. Only accessible by Admins.
        /// </summary>
        /// <param name="request">Request containing the user ID and the new role to assign.</param>
        /// <returns>Result of the role change operation.</returns>
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

        /// <summary>
        /// Changes the password for the specified user. Only the user themselves can change their password.
        /// </summary>
        /// <param name="request">Request containing the user ID and the new password.</param>
        /// <returns>Result of the password change operation.</returns>
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

        /// <summary>
        /// Soft deletes a user by their ID. Only the user themselves, or users with Admin or Manager roles, can perform this action.
        /// </summary>
        /// <param name="id">The unique identifier of the user to delete.</param>
        /// <returns>No content if successful, or an error response if not allowed or user not found.</returns>
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

        /// <summary>
        /// Restores a soft-deleted user by their ID. Only the user themselves, or users with Admin or Manager roles, can perform this action.
        /// </summary>
        /// <param name="id">The unique identifier of the user to restore.</param>
        /// <returns>Result of the restore operation.</returns>
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

        /// <summary>
        /// Confirms a user account by their ID. Only accessible by Admins and Managers.
        /// </summary>
        /// <param name="id">The unique identifier of the user to confirm.</param>
        /// <returns>Result of the confirmation operation.</returns>
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

        /// <summary>
        /// Confirms a user's email address using a confirmation token.
        /// </summary>
        /// <param name="token">The email confirmation token.</param>
        /// <returns>Result of the email confirmation operation.</returns>
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

        /// <summary>
        /// Returns the health status of the authentication service.
        /// </summary>
        /// <returns>Health status information.</returns>
        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new { status = "Healthy" });
        }
    }

}
