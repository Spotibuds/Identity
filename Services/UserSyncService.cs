using Identity.Entities;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Identity.Services;

public class UserSyncService(IMongoDatabase database, HttpClient http, IConfiguration config) : IUserSyncService
{
    public Task SyncUserToMongoDbAsync(User user, List<string> roles, CancellationToken ct = default) => UpdateUserInMongoDbAsync(user, roles, ct);

    public async Task UpdateUserInMongoDbAsync(User user, List<string> roles, CancellationToken ct = default)
    {
        var users = database.GetCollection<BsonDocument>("users");
        var filter = Builders<BsonDocument>.Filter.Eq("IdentityUserId", user.Id.ToString());
        var update = Builders<BsonDocument>.Update.Set("UserName", user.UserName).Set("IsPrivate", user.IsPrivate)
            .Set("Roles", new BsonArray(roles)).Set("UpdatedAt", DateTime.UtcNow)
            .SetOnInsert("_id", ObjectId.GenerateNewId()).SetOnInsert("IdentityUserId", user.Id.ToString())
            .SetOnInsert("CreatedAt", user.CreatedAt).SetOnInsert("DisplayName", "").SetOnInsert("Bio", "")
            .SetOnInsert("AvatarUrl", BsonNull.Value).SetOnInsert("Playlists", new BsonArray())
            .SetOnInsert("FollowedUsers", new BsonArray()).SetOnInsert("Followers", new BsonArray())
            .SetOnInsert("ListeningHistory", new BsonArray());
        await users.UpdateOneAsync(filter, update, new UpdateOptions { IsUpsert = true }, ct);
    }

    public async Task DeleteUserFromMongoDbAsync(string identityUserId)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete,
            config.Required("UserService:BaseUrl").TrimEnd('/') + "/api/users/internal/" + identityUserId);
        request.Headers.Add("X-Spotibuds-Service", config.Required("ServiceAuth:Secret"));
        using var response = await http.SendAsync(request);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException("User cleanup was not acknowledged", null, response.StatusCode);
    }

    public async Task EnsureIndexAsync(CancellationToken ct)
    {
        await database.GetCollection<BsonDocument>("users").Indexes.CreateOneAsync(
            new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys.Ascending("IdentityUserId"),
                new CreateIndexOptions { Unique = true, Name = "identity_user_unique" }), cancellationToken: ct);
    }
}
