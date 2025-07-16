namespace AuthService.Models
{
    public class LockoutSettings
    {
        public int FailedAttemptsThreshold { get; set; }
        public int LockoutMinutes { get; set; }
        public List<string> TrustedIps { get; set; } = new();
        public int UserFailedAttemptsThreshold { get; set; }
        public int UserLockoutMinutes { get; set; }
    }

}
