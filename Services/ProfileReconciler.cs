using Identity.Data;
using Identity.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Identity.Services;

public class ProfileReconciler(IdentityDbContext db, IUserSyncService sync, UserManager<User> users, TimeProvider clock,
    ILogger<ProfileReconciler> logger)
{
    public async Task EnqueueAsync(Guid userId, bool delete = false, CancellationToken ct = default)
    {
        // Immutable work rows avoid dropping a newer update while an older synchronization is in flight.
        db.ProfileSyncWork.Add(new ProfileSyncWork { UserId = userId, Delete = delete, NextAttemptAt = clock.GetUtcNow().UtcDateTime });
        await db.SaveChangesAsync(ct);
    }

    public async Task<bool> ReconcileAsync(Guid userId, CancellationToken ct = default)
    {
        // Serialize authority changes and remote writes on the same stable account row.
        // Otherwise an older in-flight sync can overwrite a newer acknowledged sync
        // after both immutable work items have been removed.
        var ownsTransaction = db.Database.CurrentTransaction == null;
        await using var transaction = ownsTransaction ? await db.Database.BeginTransactionAsync(ct) : null;
        await db.Users.Where(user => user.Id == userId)
            .ExecuteUpdateAsync(set => set.SetProperty(user => user.ConcurrencyStamp, user => user.ConcurrencyStamp), ct);
        var work = await db.ProfileSyncWork.Where(w => w.UserId == userId).OrderByDescending(w => w.Delete).FirstOrDefaultAsync(ct);
        if (work == null) return true;
        try
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Id == work.UserId, ct);
            if (user != null) await db.Entry(user).ReloadAsync(ct);
            if (work.Delete || user?.IsDeleted == true)
            {
                await sync.DeleteUserFromMongoDbAsync(work.UserId.ToString());
                if (user != null)
                {
                    var deleted = await users.DeleteAsync(user);
                    if (!deleted.Succeeded) throw new InvalidOperationException("Identity deletion not acknowledged");
                }
                db.ProfileSyncWork.RemoveRange(await db.ProfileSyncWork.Where(w => w.UserId == userId).ToListAsync(ct));
            }
            else if (user != null)
            {
                await sync.UpdateUserInMongoDbAsync(user, (await users.GetRolesAsync(user)).ToList(), ct);
                db.ProfileSyncWork.Remove(work);
            }
            else db.ProfileSyncWork.Remove(work);
            await db.SaveChangesAsync(ct);
            if (transaction != null) await transaction.CommitAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("Profile synchronization pending for {UserId}: {ErrorType}", userId, ex.GetType().Name);
            work.Attempts++;
            work.NextAttemptAt = clock.GetUtcNow().UtcDateTime.AddSeconds(Math.Min(60, 2 << Math.Min(work.Attempts, 5)));
            await db.SaveChangesAsync(ct);
            if (transaction != null) await transaction.CommitAsync(ct);
            return false;
        }
    }
}

public class ProfileSyncWorker(IServiceScopeFactory scopes, ILogger<ProfileSyncWorker> logger, TimeProvider clock) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                var reconciler = scope.ServiceProvider.GetRequiredService<ProfileReconciler>();
                var ids = await db.ProfileSyncWork.Where(w => w.NextAttemptAt <= clock.GetUtcNow().UtcDateTime)
                    .OrderBy(w => w.NextAttemptAt).Take(20).Select(w => w.UserId).Distinct().ToListAsync(stoppingToken);
                foreach (var id in ids) await reconciler.ReconcileAsync(id, stoppingToken);
                // Bound durable credential retention after expiration; keep consumed live tokens for replay detection.
                await db.RefreshTokens.Where(t => t.IsPending && t.PreparationExpiresAt < clock.GetUtcNow().UtcDateTime.AddMinutes(-1)).ExecuteDeleteAsync(stoppingToken);
                await db.RefreshTokens.Where(t => t.ExpiresAt < clock.GetUtcNow().UtcDateTime.AddDays(-1)).ExecuteDeleteAsync(stoppingToken);
                await db.SessionFamilies.Where(t => t.ExpiresAt < clock.GetUtcNow().UtcDateTime.AddDays(-1)).ExecuteDeleteAsync(stoppingToken);
                await db.PasswordResets.Where(t => t.ExpiresAt < clock.GetUtcNow().UtcDateTime.AddDays(-1)).ExecuteDeleteAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogWarning("Reconciliation delayed: {ErrorType}", ex.GetType().Name); }
            await Task.Delay(TimeSpan.FromSeconds(5), clock, stoppingToken);
        }
    }
}
