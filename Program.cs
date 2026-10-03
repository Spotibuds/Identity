using System.Net.Mail;
using System.Net.Sockets;
using System.Threading.RateLimiting;
using Identity;
using Identity.Data;
using Identity.Entities;
using Identity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MongoDB.Bson;
using MongoDB.Driver;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options => options.SingleLine = true);
var config = builder.Configuration;
foreach (var key in new[] { "ConnectionStrings:DefaultConnection", "ConnectionStrings:MongoDb", "MongoDB:DatabaseName",
    "UserService:BaseUrl", "ServiceAuth:Secret", "Frontend:PublicUrl", "Smtp:Host", "Smtp:From" }) config.Required(key);
if (config.Required("ServiceAuth:Secret").Length < 32) throw new InvalidOperationException("ServiceAuth:Secret requires at least 32 characters");
if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Test") &&
    new Uri(config.Required("Frontend:PublicUrl")).Scheme != "https")
    throw new InvalidOperationException("HTTP refresh cookies require explicit Development environment; other environments require HTTPS");
builder.Services.AddControllers();
builder.Services.AddDbContext<IdentityDbContext>(options => options.UseNpgsql(config.Required("ConnectionStrings:DefaultConnection")));
builder.Services.AddIdentityServices(config).AddSpotibudsCors(config);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<ProfileReconciler>();
builder.Services.AddScoped<IRecoveryMailer, RecoveryMailer>();
var mongoSettings = MongoClientSettings.FromConnectionString(config.Required("ConnectionStrings:MongoDb"));
mongoSettings.ServerSelectionTimeout = TimeSpan.FromSeconds(3);
mongoSettings.ConnectTimeout = TimeSpan.FromSeconds(3);
mongoSettings.SocketTimeout = TimeSpan.FromSeconds(5);
mongoSettings.MaxConnectionPoolSize = 50;
builder.Services.AddSingleton<IMongoClient>(new MongoClient(mongoSettings));
builder.Services.AddSingleton(sp => sp.GetRequiredService<IMongoClient>().GetDatabase(config.Required("MongoDB:DatabaseName")));
builder.Services.AddHttpClient<IUserSyncService, UserSyncService>(client => client.Timeout = TimeSpan.FromSeconds(5));
builder.Services.AddHostedService<ProfileSyncWorker>();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 100, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 64 * 1024);
var app = builder.Build();

if (!app.Environment.IsEnvironment("Test"))
{
    var initialized = false;
    for (var attempt = 0; attempt < 10 && !initialized; attempt++)
    {
        try
        {
            using var scope = app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            await db.Database.MigrateAsync();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
            foreach (var role in new[] { "User", "Musician", "Admin" })
                if (!await roleManager.RoleExistsAsync(role))
                {
                    var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
                    if (!result.Succeeded) throw new InvalidOperationException("Required roles could not be created");
                }
            if (config.GetValue("LocalDemo:Enabled", false))
            {
                if (!app.Environment.IsDevelopment()) throw new InvalidOperationException("LocalDemo seeding is restricted to Development");
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
                var name = config.Required("LocalDemo:AdminUsername");
                var email = config.Required("LocalDemo:AdminEmail");
                var existing = await userManager.FindByNameAsync(name);
                if (existing == null)
                {
                    await using var tx = await db.Database.BeginTransactionAsync();
                    var admin = new User { UserName = name, Email = email, LockoutEnabled = true };
                    var created = await userManager.CreateAsync(admin, config.Required("LocalDemo:AdminPassword"));
                    if (!created.Succeeded) throw new InvalidOperationException("Local administrator configuration is invalid");
                    var assigned = await userManager.AddToRoleAsync(admin, "Admin");
                    if (!assigned.Succeeded) throw new InvalidOperationException("Local administrator role assignment failed");
                    await scope.ServiceProvider.GetRequiredService<ProfileReconciler>().EnqueueAsync(admin.Id);
                    await tx.CommitAsync();
                }
                else if (!await userManager.IsInRoleAsync(existing, "Admin") || !StringComparer.OrdinalIgnoreCase.Equals(existing.Email, email))
                    throw new InvalidOperationException("LocalDemo administrator conflicts with existing account; refusing promotion");
            }
            initialized = true;
        }
        catch (Exception ex) when (ex is NpgsqlException or SocketException or TimeoutException)
        {
            app.Logger.LogWarning("PostgreSQL startup readiness attempt {Attempt}/10 failed: {ErrorType}", attempt + 1, ex.GetType().Name);
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }
    if (!initialized) throw new InvalidOperationException("PostgreSQL startup did not become ready after bounded retries");
    try
    {
        using var scope = app.Services.CreateScope();
        var sync = scope.ServiceProvider.GetRequiredService<IUserSyncService>() as UserSyncService;
        if (sync != null) await sync.EnsureIndexAsync(CancellationToken.None);
    }
    catch (MongoException ex) { app.Logger.LogWarning("MongoDB index initialization pending: {ErrorType}", ex.GetType().Name); }
}

app.Use(async (context, next) =>
{
    try { await next(context); }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
    catch (Exception ex)
    {
        var dependency = ex is NpgsqlException or MongoException or HttpRequestException or SmtpException or SocketException or TimeoutException or OperationCanceledException;
        app.Logger.LogWarning("Request {TraceId} failed: {ErrorType}", context.TraceIdentifier, ex.GetType().Name);
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = dependency ? 503 : 500;
        await context.Response.WriteAsJsonAsync(new { message = dependency ? "A local dependency is unavailable. Retry shortly." : "The operation could not be completed.", traceId = context.TraceIdentifier });
    }
});
app.UseRouting();
app.UseCors("SpotibudsPolicy");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapGet("/", () => Results.Ok(new { service = "Identity" })).AllowAnonymous();
app.MapGet("/health/live", () => Results.Ok(new { status = "live" })).AllowAnonymous();
app.MapGet("/health/ready", async (IdentityDbContext db, IMongoDatabase mongo, CancellationToken ct) =>
{
    try
    {
        if (!await db.Database.CanConnectAsync(ct) || (await db.Database.GetPendingMigrationsAsync(ct)).Any())
            return Results.Json(new { status = "not-ready" }, statusCode: 503);
        await mongo.RunCommandAsync<BsonDocument>(new BsonDocument("ping", 1), cancellationToken: ct);
        await mongo.GetCollection<BsonDocument>("users").Indexes.CreateOneAsync(new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys.Ascending("IdentityUserId"),
            new CreateIndexOptions { Unique = true, Name = "identity_user_unique" }), cancellationToken: ct);
        return Results.Ok(new { status = "ready", pendingProfiles = await db.ProfileSyncWork.CountAsync(ct) });
    }
    catch (Exception ex) when (ex is not OperationCanceledException) { return Results.Json(new { status = "not-ready" }, statusCode: 503); }
}).AllowAnonymous();
app.Run();

public partial class Program { }
