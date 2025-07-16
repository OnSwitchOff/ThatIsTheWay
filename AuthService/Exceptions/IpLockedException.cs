namespace AuthService.Exceptions
{
    public class IpLockedException : Exception
    {
        public int RetryAfterMinutes { get; }
        public IpLockedException(int retryAfterMinutes)
            : base($"Too many failed login attempts. Try again in {retryAfterMinutes} minutes.")
        {
            RetryAfterMinutes = retryAfterMinutes;
        }
    }
}
