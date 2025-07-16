namespace AuthService.Models
{
    public class LoginAttempt
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid? UserId { get; set; }
        public string? UsernameAttempted { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string? IpAddress { get; set; }
        public bool IsSuccessful { get; set; }
        public string? Reason { get; set; }
        public string? Country { get; set; }
        public string? Region { get; set; }
    }

}
