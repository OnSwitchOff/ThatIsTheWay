using Microsoft.Extensions.Logging;

namespace AuthService.Services
{
    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;

        public EmailService(ILogger<EmailService> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string to, string subject, string body)
        {
            _logger.LogInformation("Sending email to {To}: {Subject}\n{Body}", to, subject, body);
            // TODO: Implement actual email sending (SMTP, SendGrid, etc.)
            return Task.CompletedTask;
        }
    }
}