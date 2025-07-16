using System.Text.Json;

namespace AuthService.Services
{
    public class GeoIpService : IGeoIpService
    {
        private readonly HttpClient _httpClient;

        public GeoIpService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<(string Country, string Region)> GetInfo(string ip)
        {
            var url = $"http://ip-api.com/json/{ip}";
            var response = await _httpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string country = root.GetProperty("country").GetString() ?? "";
            string region = root.GetProperty("regionName").GetString() ?? "";

            return (country, region);
        }
    }

}
