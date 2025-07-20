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

    public UserSyncService(HttpClient httpClient, ILogger<UserSyncService> logger, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _logger = logger;
        var mongoConnectionString = configuration.GetConnectionString("MongoDb");
        var mongoClient = new MongoClient(mongoConnectionString);
        var mongoDatabase = mongoClient.GetDatabase("spotibuds");
        _usersCollection = mongoDatabase.GetCollection<BsonDocument>("users");
    }

    public async Task SyncUserToMongoDbAsync(User identityUser)
    {
        try
        {
            var userDoc = new BsonDocument
            {
                { "IdentityUserId", identityUser.Id.ToString() },
                { "UserName", identityUser.UserName ?? string.Empty },
                { "Email", identityUser.Email ?? string.Empty },
                { "IsPrivate", identityUser.IsPrivate }
            };
            await _usersCollection.InsertOneAsync(userDoc);
            _logger.LogInformation("Successfully synced user {UserId} to MongoDB", identityUser.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while syncing user {UserId} to MongoDB", identityUser.Id);
        }
    }

    public async Task UpdateUserInMongoDbAsync(User identityUser)
    {
        try
        {
            var filter = Builders<BsonDocument>.Filter.Eq("IdentityUserId", identityUser.Id.ToString());
            var update = Builders<BsonDocument>.Update
                .Set("UserName", identityUser.UserName ?? string.Empty)
                .Set("Email", identityUser.Email ?? string.Empty)
                .Set("IsPrivate", identityUser.IsPrivate);
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
            _logger.LogError(ex, "Exception occurred while updating user {UserId} in MongoDB", identityUser.Id);
        }
    }

    public async Task DeleteUserFromMongoDbAsync(string identityUserId)
    {
        try
        {
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
            _logger.LogError(ex, "Exception occurred while deleting user {UserId} in MongoDB", identityUserId);
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