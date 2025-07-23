using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Identity.Data;
using Identity.Services;
using Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Get connection string from configuration or environment variable
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection");

if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Database connection string not found. Please set ConnectionStrings__DefaultConnection environment variable.");
}

builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddIdentityServices(builder.Configuration);

builder.Services.AddSpotibudsCors(builder.Configuration);

builder.Services.AddAuthorization();

builder.Services.AddHttpClient<IUserSyncService, UserSyncService>();
builder.Services.AddScoped<IUserSyncService, UserSyncService>();

//listen port 80

builder.WebHost.UseUrls("http://0.0.0.0:80");

var app = builder.Build();

// Initialize roles with error handling
try
{
    using (var scope = app.Services.CreateScope())
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        
        // Test database connection first
        if (await dbContext.Database.CanConnectAsync())
        {
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

            string[] roles = { "User", "Musician", "Admin" };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole<Guid>(role));
                }
            }
            logger.LogInformation("Role initialization completed successfully.");
        }
        else
        {
            logger.LogWarning("Database connection failed. Skipping role initialization.");
        }
    }
}
catch (Exception ex)
{
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogError(ex, "Failed to initialize roles. Application will continue without role setup.");
}
app.UseSwagger();
app.UseSwaggerUI();

app.UseCors("SpotibudsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.MapGet("/", () => "Identity API is running!");
app.MapGet("/health", () => new { status = "healthy", timestamp = DateTime.UtcNow });

app.Run();
