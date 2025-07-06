using Identity.Entities;

namespace Identity.Services;

public interface IUserSyncService
{
    Task SyncUserToMongoDbAsync(User identityUser);
    Task UpdateUserInMongoDbAsync(User identityUser);
    Task DeleteUserFromMongoDbAsync(string identityUserId);
} 