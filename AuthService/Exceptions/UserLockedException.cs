namespace AuthService.Exceptions
{
    public class UserLockedException : Exception
    {
        public int RetryAfterMinutes { get; }
        public UserLockedException(int retryAfterMinutes)
            : base($"Account is locked due to too many failed login attempts. Try again in {retryAfterMinutes} minutes.")
        {
            RetryAfterMinutes = retryAfterMinutes;
        }
    }
}
