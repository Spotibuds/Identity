using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Identity.Data;
using Identity.Services;
using Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityServices(builder.Configuration);

builder.Services.AddSpotibudsCors(builder.Configuration);

builder.Services.AddAuthorization();

builder.Services.AddHttpClient<IUserSyncService, UserSyncService>();
builder.Services.AddScoped<IUserSyncService, UserSyncService>();

//listen port 80

builder.WebHost.UseUrls("http://0.0.0.0:80");

var app = builder.Build();

using (var scope = app.Services.CreateScope())
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