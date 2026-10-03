using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Identity.Data;

// Schema generation never starts the server or connects to an external database.
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args) => new(new DbContextOptionsBuilder<IdentityDbContext>()
        .UseNpgsql("Host=127.0.0.1;Database=spotibuds_schema_only;Username=schema_only;Password=not-a-credential").Options);
}
