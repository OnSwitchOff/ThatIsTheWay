using Microsoft.Extensions.Logging;

namespace AuthService.Services
{
    /// <summary>
    /// Provides email sending functionality for the authentication service.
    /// </summary>
    public class EmailService(ILogger<EmailService> logger) : IEmailService
    {
        /// <summary>
        /// The logger instance for logging email operations.
        /// </summary>
        private readonly ILogger<EmailService> _logger = logger;

        /// <summary>
        /// Sends an email asynchronously.
        /// </summary>
        /// <param name="to">The recipient's email address.</param>
        /// <param name="subject">The subject of the email.</param>
        /// <param name="body">The body content of the email.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public Task SendEmailAsync(string to, string subject, string body)
        {
            _logger.LogInformation("Sending email to {To}: {Subject}\n{Body}", to, subject, body);
            // TODO: Implement actual email sending (SMTP, SendGrid, etc.)
            return Task.CompletedTask;
        }
    }
}