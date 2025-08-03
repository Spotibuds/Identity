using Identity.Entities;

namespace Identity.Services;

public interface IUserSyncService
{
    Task SyncUserToMongoDbAsync(User identityUser, CancellationToken cancellationToken = default);
    Task UpdateUserInMongoDbAsync(User identityUser);
    Task DeleteUserFromMongoDbAsync(string identityUserId);
} 