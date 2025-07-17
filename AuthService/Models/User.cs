namespace AuthService.Models
{
    /// <summary>
    /// Represents a user in the authentication service.
    /// </summary>
    public class User
    {
        /// <summary>
        /// Gets or sets the unique identifier for the user.
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Gets or sets the email address of the user.
        /// </summary>
        public required string Email { get; set; }

        /// <summary>
        /// Gets or sets the password hash of the user.
        /// </summary>
        public required string PasswordHash { get; set; }

        /// <summary>
        /// Gets or sets the username of the user.
        /// </summary>
        public string Username { get; set; } = default!;

        /// <summary>
        /// Gets or sets the role of the user.
        /// </summary>
        public Role Role { get; set; } = Role.User;

        /// <summary>
        /// Gets or sets a value indicating whether the user must change their password.
        /// </summary>
        public bool MustChangePassword { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the user is deleted.
        /// </summary>
        public bool IsDeleted { get; set; } = false;

        /// <summary>
        /// Gets or sets the date and time when the user was deleted.
        /// </summary>
        public DateTime? DateDeleted { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the user's email is confirmed.
        /// </summary>
        public bool IsConfirmed { get; set; } = false;

        /// <summary>
        /// Gets or sets the email confirmation token for the user.
        /// </summary>
        public string? EmailConfirmationToken { get; set; }

        /// <summary>
        /// Gets or sets the expiry date and time of the email confirmation token.
        /// </summary>
        public DateTime? EmailConfirmationTokenExpiry { get; set; }

        /// <summary>
        /// Gets or sets the full name of the user.
        /// </summary>
        public string FullName { get; set; } = default!;

        /// <summary>
        /// Gets or sets the date and time when the user was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }
    }
}
