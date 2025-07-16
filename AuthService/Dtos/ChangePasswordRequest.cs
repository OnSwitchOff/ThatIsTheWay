namespace AuthService.Dtos
{
    public class ChangePasswordRequest
    {
        public Guid UserId { get; set; }
        public string NewPassword { get; set; } = string.Empty;
    }
}
