namespace AuthService.Models
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }

        // В будущем можно добавить:
        public string? Username { get; set; }
        public string? FullName { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public Role Role { get; set; } = Role.User;
        public bool MustChangePassword { get; set; } = false;
    }

}
