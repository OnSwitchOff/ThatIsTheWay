namespace AuthService.Services
{
    public interface IGeoIpService
    {
        Task<(string Country, string Region)> GetInfo(string ip);
    }

}
