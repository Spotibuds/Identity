using Identity.Entities;
using System.Text;
using System.Text.Json;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Identity.Services;

public class UserSyncService : IUserSyncService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UserSyncService> _logger;
    private readonly IMongoCollection<BsonDocument> _usersCollection;
    private readonly string _connectionString;

    public UserSyncService(HttpClient httpClient, ILogger<UserSyncService> logger, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _logger = logger;
        
        var mongoConnectionString = configuration.GetConnectionString("MongoDb");
        if (string.IsNullOrEmpty(mongoConnectionString))
        {
            throw new InvalidOperationException("MongoDB connection string not found. Please set ConnectionStrings__MongoDb environment variable.");
        }
        
        // Fix the connection string - remove authMechanism=DEFAULT which can cause issues
        _connectionString = mongoConnectionString.Replace("&authMechanism=DEFAULT", "").Replace("?authMechanism=DEFAULT&", "?").Replace("?authMechanism=DEFAULT", "");
        
        _logger.LogInformation("Initializing MongoDB connection...");
        
        try
        {
            var mongoClient = new MongoClient(_connectionString);
            var mongoDatabase = mongoClient.GetDatabase("spotibuds");
            _usersCollection = mongoDatabase.GetCollection<BsonDocument>("users");
            
            _logger.LogInformation("MongoDB client initialized successfully. Connection will be tested on first use.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize MongoDB client. This is required for user synchronization.");
            throw new InvalidOperationException($"MongoDB client initialization failed: {ex.Message}", ex);
        }
    }

    private async Task<bool> TestConnectionAsync()
    {
        try
        {
            _logger.LogInformation("Testing MongoDB connection...");
            var mongoClient = new MongoClient(_connectionString);
            var mongoDatabase = mongoClient.GetDatabase("spotibuds");
            
            // Use a simpler ping command
            var result = await mongoDatabase.RunCommandAsync<BsonDocument>(new BsonDocument("ping", 1));
            _logger.LogInformation("MongoDB connection test successful: {Result}", result.ToJson());
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MongoDB connection test failed");
            return false;
        }
    }

    public async Task SyncUserToMongoDbAsync(User identityUser)
    {
        try
        {
            _logger.LogInformation("Starting MongoDB sync for user {UserId}", identityUser.Id);
            
            // Test connection before first use
            if (!await TestConnectionAsync())
            {
                throw new InvalidOperationException("MongoDB connection test failed before user sync");
            }
            
            var userDoc = new BsonDocument
            {
                { "IdentityUserId", identityUser.Id.ToString() },
                { "UserName", identityUser.UserName ?? string.Empty },
                { "Email", identityUser.Email ?? string.Empty },
                { "IsPrivate", identityUser.IsPrivate },
                { "CreatedAt", identityUser.CreatedAt }
            };
            
            await _usersCollection.InsertOneAsync(userDoc);
            _logger.LogInformation("Successfully synced user {UserId} to MongoDB", identityUser.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync user {UserId} to MongoDB", identityUser.Id);
            throw; // Re-throw the exception so registration can handle it appropriately
        }
    }

    public async Task UpdateUserInMongoDbAsync(User identityUser)
    {
        try
        {
            _logger.LogInformation("Starting MongoDB update for user {UserId}", identityUser.Id);
            
            var filter = Builders<BsonDocument>.Filter.Eq("IdentityUserId", identityUser.Id.ToString());
            var update = Builders<BsonDocument>.Update
                .Set("UserName", identityUser.UserName ?? string.Empty)
                .Set("Email", identityUser.Email ?? string.Empty)
                .Set("IsPrivate", identityUser.IsPrivate)
                .Set("UpdatedAt", DateTime.UtcNow);
                
            var result = await _usersCollection.UpdateOneAsync(filter, update);
            if (result.MatchedCount == 0)
            {
                _logger.LogWarning("User {UserId} not found in MongoDB, creating new entry", identityUser.Id);
                await SyncUserToMongoDbAsync(identityUser);
            }
            else
            {
                _logger.LogInformation("Successfully updated user {UserId} in MongoDB", identityUser.Id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update user {UserId} in MongoDB", identityUser.Id);
            throw; // Re-throw the exception
        }
    }

    public async Task DeleteUserFromMongoDbAsync(string identityUserId)
    {
        try
        {
            _logger.LogInformation("Starting MongoDB deletion for user {UserId}", identityUserId);
            
            var filter = Builders<BsonDocument>.Filter.Eq("IdentityUserId", identityUserId);
            var result = await _usersCollection.DeleteOneAsync(filter);
            if (result.DeletedCount == 0)
            {
                _logger.LogWarning("User {UserId} not found in MongoDB for deletion", identityUserId);
            }
            else
            {
                _logger.LogInformation("Successfully deleted user {UserId} from MongoDB", identityUserId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete user {UserId} from MongoDB", identityUserId);
            throw; // Re-throw the exception
        }
    }
}

public class CreateUserForMongoDto
{
    public string IdentityUserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public bool IsPrivate { get; set; } = false;
}

public class UpdateUserForMongoDto
{
    public string? UserName { get; set; }
    public bool? IsPrivate { get; set; }
}

public class MongoUserDto
{
    public string Id { get; set; } = string.Empty;
    public string IdentityUserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public bool IsPrivate { get; set; }
    public DateTime CreatedAt { get; set; }
} 