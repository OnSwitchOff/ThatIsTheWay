namespace AuthService.Dtos
{
    public class LoginResponseDto
    {
        public string Token { get; set; } = default!;
        public string Username { get; set; } = default!;
        public Guid UserId { get; set; }
        public bool RequiresPasswordChange { get; set; } = default!;
    }

}
