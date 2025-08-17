using Identity.Entities;

namespace Identity.Services;

public interface IUserSyncService
{
    Task SyncUserToMongoDbAsync(User identityUser,List<string> roles, CancellationToken cancellationToken = default);
    Task UpdateUserInMongoDbAsync(User identityUser, List<string> roles, CancellationToken cancellationToken = default);
    Task DeleteUserFromMongoDbAsync(string identityUserId);
} 