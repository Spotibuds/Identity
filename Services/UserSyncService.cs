using Identity.Entities;
using System.Text;
using System.Text.Json;

namespace Identity.Services;

public class UserSyncService : IUserSyncService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UserSyncService> _logger;
    private readonly string _userServiceUrl;

    public UserSyncService(HttpClient httpClient, ILogger<UserSyncService> logger, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _logger = logger;
        _userServiceUrl = configuration.GetConnectionString("UserService") ?? "http://localhost:5003";
    }

    public async Task SyncUserToMongoDbAsync(User identityUser)
    {
        try
        {
            var createUserDto = new CreateUserForMongoDto
            {
                IdentityUserId = identityUser.Id.ToString(),
                UserName = identityUser.UserName ?? string.Empty,
                IsPrivate = identityUser.IsPrivate
            };

            var json = JsonSerializer.Serialize(createUserDto);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"{_userServiceUrl}/api/users", content);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Successfully synced user {UserId} to MongoDB", identityUser.Id);
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to sync user {UserId} to MongoDB. Status: {StatusCode}, Error: {Error}", 
                    identityUser.Id, response.StatusCode, errorContent);
            }
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
            var findResponse = await _httpClient.GetAsync($"{_userServiceUrl}/api/users/identity/{identityUser.Id}");
            
            if (!findResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning("User {UserId} not found in MongoDB, creating new entry", identityUser.Id);
                await SyncUserToMongoDbAsync(identityUser);
                return;
            }

            var mongoUserJson = await findResponse.Content.ReadAsStringAsync();
            var mongoUser = JsonSerializer.Deserialize<MongoUserDto>(mongoUserJson);

            if (mongoUser != null)
            {
                var updateUserDto = new UpdateUserForMongoDto
                {
                    UserName = identityUser.UserName,
                    IsPrivate = identityUser.IsPrivate
                };

                var json = JsonSerializer.Serialize(updateUserDto);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PutAsync($"{_userServiceUrl}/api/users/{mongoUser.Id}", content);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Successfully updated user {UserId} in MongoDB", identityUser.Id);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Failed to update user {UserId} in MongoDB. Status: {StatusCode}, Error: {Error}", 
                        identityUser.Id, response.StatusCode, errorContent);
                }
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
            var findResponse = await _httpClient.GetAsync($"{_userServiceUrl}/api/users/identity/{identityUserId}");
            
            if (!findResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning("User {UserId} not found in MongoDB for deletion", identityUserId);
                return;
            }

            var mongoUserJson = await findResponse.Content.ReadAsStringAsync();
            var mongoUser = JsonSerializer.Deserialize<MongoUserDto>(mongoUserJson);

            if (mongoUser != null)
            {
                var response = await _httpClient.DeleteAsync($"{_userServiceUrl}/api/users/{mongoUser.Id}");

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Successfully deleted user {UserId} from MongoDB", identityUserId);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Failed to delete user {UserId} from MongoDB. Status: {StatusCode}, Error: {Error}", 
                        identityUserId, response.StatusCode, errorContent);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while deleting user {UserId} from MongoDB", identityUserId);
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