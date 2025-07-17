namespace AuthService.Models
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }
        public string Username { get; set; } = default!;
        public Role Role { get; set; } = Role.User;
        public bool MustChangePassword { get; set; } = false;
        public bool IsDeleted { get; set; } = false;
        public DateTime? DateDeleted { get; set; }
        public bool IsConfirmed { get; set; } = false;
        public string? EmailConfirmationToken { get; set; } 
        public DateTime? EmailConfirmationTokenExpiry { get; set; } 
        public string FullName { get; set; } = default!;
        public DateTime CreatedAt { get; set; }
    }

}
