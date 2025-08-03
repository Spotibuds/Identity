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
builder.WebHost.UseUrls($"http://0.0.0.0:5000");

var app = builder.Build();

// Apply database migrations and initialize roles with comprehensive error handling
try
{
    using (var scope = app.Services.CreateScope())
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        
        logger.LogInformation("Starting database initialization...");
        
        // Test database connection first
        if (await dbContext.Database.CanConnectAsync())
        {
            logger.LogInformation("Database connection successful. Applying migrations...");
            
            // Apply any pending migrations
            await dbContext.Database.MigrateAsync();
            logger.LogInformation("Database migrations applied successfully.");
            
            // Initialize roles
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

            string[] roles = { "User", "Musician", "Admin" };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
                    if (result.Succeeded)
                    {
                        logger.LogInformation("Created role: {Role}", role);
                    }
                    else
                    {
                        logger.LogError("Failed to create role {Role}: {Errors}", role, string.Join(", ", result.Errors.Select(e => e.Description)));
                    }
                }
                else
                {
                    logger.LogInformation("Role {Role} already exists", role);
                }
            }
            logger.LogInformation("Role initialization completed successfully.");
        }
        else
        {
            logger.LogError("Database connection failed. Database initialization skipped.");
            logger.LogError("Connection string: {ConnectionString}", connectionString?.Substring(0, Math.Min(50, connectionString.Length)) + "...");
        }
    }
}
catch (Exception ex)
{
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogError(ex, "Failed to initialize database and roles. Application will continue with limited functionality.");
    logger.LogError("Exception details: {ExceptionType}: {Message}", ex.GetType().Name, ex.Message);
    if (ex.InnerException != null)
    {
        logger.LogError("Inner exception: {InnerExceptionType}: {InnerMessage}", ex.InnerException.GetType().Name, ex.InnerException.Message);
    }
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseCors("SpotibudsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.MapGet("/", () => "Identity API is running!");
app.MapGet("/health", async (HttpContext context) => 
{
    var dbContext = context.RequestServices.GetRequiredService<IdentityDbContext>();
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    
    try
    {
        var canConnect = await dbContext.Database.CanConnectAsync();
        var pendingMigrations = await dbContext.Database.GetPendingMigrationsAsync();
        
        return Results.Ok(new { 
            status = canConnect ? "healthy" : "unhealthy",
            timestamp = DateTime.UtcNow,
            database = new {
                connected = canConnect,
                pendingMigrations = pendingMigrations.Count(),
                migrations = pendingMigrations
            }
        });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Health check failed");
        return Results.Ok(new { 
            status = "unhealthy", 
            timestamp = DateTime.UtcNow,
            error = ex.Message 
        });
    }
});

app.Run();
