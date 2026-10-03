using System.Security.Claims;
using System.Text;
using Identity.Data;
using Identity.Entities;
using Identity.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Identity;

public static class IdentityServiceExtensions
{
    public static string Required(this IConfiguration config, string key) =>
        !string.IsNullOrWhiteSpace(config[key]) ? config[key]! : throw new InvalidOperationException($"Required configuration missing: {key}");

    public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
    {
        var secret = configuration.Required("Jwt:Secret");
        if (Encoding.UTF8.GetByteCount(secret) < 32) throw new InvalidOperationException("Jwt:Secret must contain at least 32 bytes");
        var issuer = configuration.Required("Jwt:Issuer");
        var audience = configuration.Required("Jwt:Audience");
        services.AddIdentityCore<User>(options =>
        {
            options.Password.RequiredLength = 8;
            options.Password.RequiredUniqueChars = 6;
            options.User.RequireUniqueEmail = true;
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            options.Lockout.AllowedForNewUsers = true;
        }).AddRoles<IdentityRole<Guid>>().AddEntityFrameworkStores<IdentityDbContext>().AddSignInManager();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true, ValidateAudience = true, ValidateLifetime = true, ValidateIssuerSigningKey = true,
                ValidIssuer = issuer, ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ClockSkew = TimeSpan.FromSeconds(5),
                NameClaimType = ClaimTypes.Name, RoleClaimType = ClaimTypes.Role
            };
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    if (!Guid.TryParse(context.Principal?.FindFirstValue("sid"), out var family)) { context.Fail("Session missing"); return; }
                    var sessions = context.HttpContext.RequestServices.GetRequiredService<SessionService>();
                    if (!await sessions.IsActiveAsync(family, context.HttpContext.RequestAborted)) context.Fail("Session revoked");
                }
            };
        });
        services.AddAuthorization(options => options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
        return services;
    }

    public static IServiceCollection AddSpotibudsCors(this IServiceCollection services, IConfiguration configuration)
    {
        var origins = configuration.Required("Cors:AllowedOrigins").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (origins.Length == 0 || origins.Any(origin => origin == "*" || !Uri.TryCreate(origin, UriKind.Absolute, out _)))
            throw new InvalidOperationException("Cors:AllowedOrigins must contain explicit origins");
        services.AddCors(options => options.AddPolicy("SpotibudsPolicy", policy => policy.WithOrigins(origins)
            .WithHeaders("Authorization", "Content-Type", "X-Spotibuds-Request", "X-Spotibuds-Refresh-Request").WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS").AllowCredentials()));
        return services;
    }
}
