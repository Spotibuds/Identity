using System.Collections.Concurrent;
using Identity.Data;
using Identity.Entities;
using Identity.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Identity.Tests;

public sealed class IdentityFactory : WebApplicationFactory<Program>
{
    // Minimal-host configuration is read before the WAF app-configuration callback.
    // These values live only in the isolated dotnet-test process and never reach a real store.
    static IdentityFactory()
    {
        foreach (var pair in new Dictionary<string, string>
        {
            ["ConnectionStrings__DefaultConnection"] = "Host=127.0.0.1;Database=test-only;Username=test;Password=test-only",
            ["ConnectionStrings__MongoDb"] = "mongodb://127.0.0.1:1", ["MongoDB__DatabaseName"] = "identity_test_only",
            ["Jwt__Secret"] = "test-only-secret-key-at-least-32-bytes-123456789",
            ["Jwt__Issuer"] = "test-issuer", ["Jwt__Audience"] = "test-audience",
            ["Cors__AllowedOrigins"] = "http://127.0.0.1:3100", ["Frontend__PublicUrl"] = "http://127.0.0.1:3100",
            ["UserService__BaseUrl"] = "http://127.0.0.1:1", ["ServiceAuth__Secret"] = ServiceSecret,
            ["Smtp__Host"] = "127.0.0.1", ["Smtp__From"] = "test@spotibuds.local"
        }) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
    }
    private readonly string connectionString = $"Data Source=identity-{Guid.NewGuid()};Mode=Memory;Cache=Shared";
    private readonly SqliteConnection keeper;
    public FakeSync Sync { get; } = new();
    public FakeMailer Mailer { get; } = new();
    public TestClock Clock { get; } = new();
    public const string ServiceSecret = "test-service-only-random-enough-123456789";

    public IdentityFactory() { keeper = new SqliteConnection(connectionString); keeper.Open(); }
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:DefaultConnection"] = "Host=127.0.0.1;Database=test-only;Username=test;Password=test-only",
            ["ConnectionStrings:MongoDb"] = "mongodb://127.0.0.1:1",
            ["MongoDB:DatabaseName"] = "identity_test_only",
            ["Jwt:Secret"] = "test-only-secret-key-at-least-32-bytes-123456789",
            ["Jwt:Issuer"] = "test-issuer", ["Jwt:Audience"] = "test-audience",
            ["Cors:AllowedOrigins"] = "http://127.0.0.1:3100",
            ["Frontend:PublicUrl"] = "http://127.0.0.1:3100",
            ["UserService:BaseUrl"] = "http://127.0.0.1:1", ["ServiceAuth:Secret"] = ServiceSecret,
            ["Smtp:Host"] = "127.0.0.1", ["Smtp:From"] = "test@spotibuds.local",
            ["AllowedHosts"] = "*", ["Logging:LogLevel:Default"] = "Warning"
        }));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IdentityDbContext>();
            services.RemoveAll<DbContextOptions<IdentityDbContext>>();
            foreach (var descriptor in services.Where(s => s.ServiceType.FullName?.Contains("IDbContextOptionsConfiguration") == true).ToList()) services.Remove(descriptor);
            services.AddDbContext<IdentityDbContext>(options => options.UseSqlite(connectionString));
            services.RemoveAll<IUserSyncService>(); services.AddSingleton<IUserSyncService>(Sync);
            services.RemoveAll<IRecoveryMailer>(); services.AddSingleton<IRecoveryMailer>(Mailer);
            services.RemoveAll<TimeProvider>(); services.AddSingleton<TimeProvider>(Clock);
            foreach (var descriptor in services.Where(s => s.ServiceType == typeof(IHostedService) && s.ImplementationType == typeof(ProfileSyncWorker)).ToList()) services.Remove(descriptor);
        });
    }

    public async Task InitializeAsync()
    {
        using var scope = Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreatedAsync();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        foreach (var role in new[] { "User", "Admin", "Musician" }) await roleManager.CreateAsync(new IdentityRole<Guid>(role));
    }

    public async Task<T> InspectAsync<T>(Func<IdentityDbContext, Task<T>> inspect)
    {
        using var scope = Services.CreateScope();
        return await inspect(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    public async Task MakeAdminAsync(Guid id)
    {
        using var scope = Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var user = (await manager.FindByIdAsync(id.ToString()))!;
        await manager.RemoveFromRoleAsync(user, "User");
        await manager.AddToRoleAsync(user, "Admin");
    }

    protected override void Dispose(bool disposing) { base.Dispose(disposing); if (disposing) keeper.Dispose(); }
}

public sealed class TestClock : TimeProvider
{
    public DateTimeOffset Value { get; set; } = DateTimeOffset.UtcNow;
    public override DateTimeOffset GetUtcNow() => Value;
}

public sealed class FakeSync : IUserSyncService
{
    public bool Fail { get; set; }
    public ConcurrentDictionary<Guid, (string Name, bool Private, string[] Roles)> Profiles { get; } = new();
    public Task SyncUserToMongoDbAsync(User user, List<string> roles, CancellationToken cancellationToken = default) => UpdateUserInMongoDbAsync(user, roles, cancellationToken);
    public Task UpdateUserInMongoDbAsync(User user, List<string> roles, CancellationToken cancellationToken = default)
    {
        if (Fail) throw new HttpRequestException("Synthetic unavailable dependency");
        Profiles[user.Id] = (user.UserName!, user.IsPrivate, roles.ToArray());
        return Task.CompletedTask;
    }
    public Task DeleteUserFromMongoDbAsync(string id)
    {
        if (Fail) throw new HttpRequestException("Synthetic unavailable dependency");
        Profiles.TryRemove(Guid.Parse(id), out _);
        return Task.CompletedTask;
    }
}

public sealed class FakeMailer : IRecoveryMailer
{
    public bool Fail { get; set; }
    public string? Token { get; private set; }
    public string? Email { get; private set; }
    public Task CheckAvailableAsync(CancellationToken ct) => Fail ? throw new System.Net.Mail.SmtpException("Synthetic mail outage") : Task.CompletedTask;
    public Task SendAsync(string email, string token, CancellationToken ct) { Email = email; Token = token; return Task.CompletedTask; }
}
