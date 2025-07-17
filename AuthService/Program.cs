using AspNetCoreRateLimit;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Explicitly configure Kestrel to listen on 8080 (HTTP) and 8081 (HTTPS)
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8080); // HTTP
    options.ListenAnyIP(8081, listenOptions => listenOptions.UseHttps()); // HTTPS
});

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.Configure<LockoutSettings>(builder.Configuration.GetSection("LockoutSettings"));

builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.AddInMemoryRateLimiting();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

builder.Services.AddHttpClient<IGeoIpService, GeoIpService>();
builder.Services.AddScoped<IEmailService, EmailService>();

// Add this line to read the JWT key from configuration
var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT key not configured.");

// Update DI registration for AuthService
builder.Services.AddScoped<AuthService.Services.AuthService>(sp =>
{
    var dbContext = sp.GetRequiredService<AuthDbContext>();
    var lockoutOptions = sp.GetRequiredService<IOptions<LockoutSettings>>();
    var geoIpService = sp.GetRequiredService<IGeoIpService>();
    var emailService = sp.GetRequiredService<IEmailService>();
    var cache = sp.GetRequiredService<IMemoryCache>();
    return new AuthService.Services.AuthService(dbContext, jwtKey, lockoutOptions, geoIpService, emailService, cache);
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateLifetime = true,
        };
    });

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHostedService<AuthService.Services.UserCleanupService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseIpRateLimiting();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();