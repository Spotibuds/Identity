using Npgsql;

namespace Identity;

public static class TestConnection
{
    public static async Task<bool> TestPostgreSQLConnection(string connectionString)
    {
        try
        {
            using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            Console.WriteLine("✅ PostgreSQL connection successful!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ PostgreSQL connection failed: {ex.Message}");
            return false;
        }
    }
}
