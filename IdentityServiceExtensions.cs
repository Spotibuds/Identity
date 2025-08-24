using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Identity.Data;
using Identity.Entities;
using System.Text;

namespace Identity
{
    public static class IdentityServiceExtensions
    {
        public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddIdentity<User, IdentityRole<Guid>>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequiredUniqueChars = 6;

                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedEmail = false;

                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<IdentityDbContext>()
            .AddDefaultTokenProviders();

            var secretKey = configuration["Jwt:Secret"] ?? throw new InvalidOperationException("JWT Secret not configured");
            if (secretKey.Length < 32)
            {
                throw new InvalidOperationException("JWT Secret must be at least 32 characters long");
            }

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    ValidAudience = configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                    ClockSkew = TimeSpan.FromMinutes(5)
                };
            });

            return services;
        }

        public static IServiceCollection AddSpotibudsCors(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("SpotibudsPolicy", policy =>
                    {
                        var allowedOrigins = configuration["Cors:AllowedOrigins"];
                        if (!string.IsNullOrEmpty(allowedOrigins))
                        {
                            if (allowedOrigins == "*")
                            {
                                // For development only - no credentials with wildcard
                                policy.AllowAnyOrigin()
                                      .AllowAnyHeader()
                                      .AllowAnyMethod();
                            }
                            else
                            {
                                var origins = allowedOrigins.Split(',', StringSplitOptions.RemoveEmptyEntries);
                                policy.WithOrigins(origins)
                                      .AllowAnyHeader()
                                      .AllowAnyMethod()
                                      .AllowCredentials(); // Allow credentials for specific origins
                            }
                        }
                        else
                        {
                            // Default to localhost for development
                            policy.WithOrigins("http://localhost:3000", "https://localhost:3000")
                                  .AllowAnyHeader()
                                  .AllowAnyMethod()
                                  .AllowCredentials();
                        }
                    });
            });

            return services;
        }
    }
}