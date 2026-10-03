using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Identity.Data;
using Identity.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Services;

public class SessionService(IdentityDbContext db, UserManager<User> users, IConfiguration config, TimeProvider clock)
{
    public const string CookieName = "spotibuds.refresh";
    public static string NewCredential() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public const int PreparationSeconds = 30;
    public DateTime Now => clock.GetUtcNow().UtcDateTime;

    public async Task<bool> IsActiveAsync(Guid family, CancellationToken ct = default) =>
        await db.SessionFamilies.AnyAsync(t => t.Id == family && !t.IsRevoked && t.ExpiresAt > Now && !t.User.IsDeleted, ct);

    public async Task RevokeUserAsync(Guid userId, CancellationToken ct = default)
    {
        await db.SessionFamilies.Where(t => t.UserId == userId && !t.IsRevoked).ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
        await db.RefreshTokens.Where(t => t.UserId == userId && !t.IsRevoked).ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
    }

    public async Task RevokeFamilyAsync(Guid family, CancellationToken ct = default)
    {
        await db.SessionFamilies.Where(t => t.Id == family && !t.IsRevoked).ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
        await db.RefreshTokens.Where(t => t.FamilyId == family && !t.IsRevoked).ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
    }

    public async Task RevokeCredentialAsync(string credential, CancellationToken ct = default)
    {
        var hash = Hash(credential);
        var family = await db.RefreshTokens.Where(t => t.Token == hash).Select(t => (Guid?)t.FamilyId).SingleOrDefaultAsync(ct);
        if (family.HasValue) await RevokeFamilyAsync(family.Value, ct);
    }

    public async Task<SessionResult> CreateAsync(User user, Guid? family = null, CancellationToken ct = default)
    {
        var credential = NewCredential();
        var session = new RefreshToken
        {
            UserId = user.Id, Token = Hash(credential), FamilyId = family ?? Guid.NewGuid(),
            ExpiresAt = Now.AddDays(7), CreatedAt = Now
        };
        if (family == null) db.SessionFamilies.Add(new SessionFamily { Id = session.FamilyId, UserId = user.Id, ExpiresAt = session.ExpiresAt });
        db.RefreshTokens.Add(session);
        await db.SaveChangesAsync(ct);
        return await ResultAsync(user, session, credential);
    }

    public async Task<SessionResult?> RotateAsync(string credential, CancellationToken ct = default)
    {
        if (credential.Length is < 40 or > 256) return null;
        var hash = Hash(credential);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var current = await db.RefreshTokens.AsNoTracking().Include(t => t.User).SingleOrDefaultAsync(t => t.Token == hash, ct);
        if (current == null || current.ExpiresAt <= Now || current.User.IsDeleted || current.IsPending) return null;
        var locked = await db.SessionFamilies.Where(f => f.Id == current.FamilyId && !f.IsRevoked && f.ExpiresAt > Now)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.UpdatedAt, Now), ct);
        if (locked != 1) return null;
        if (current.IsRevoked)
        {
            // Strict replay policy: a consumed credential revokes its entire family, including its successor.
            await RevokeFamilyAsync(current.FamilyId, ct);
            await transaction.CommitAsync(ct);
            return null;
        }
        var nextId = Guid.NewGuid();
        var consumed = await db.RefreshTokens.Where(t => t.Id == current.Id && !t.IsRevoked && t.ExpiresAt > Now)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true).SetProperty(t => t.ReplacedById, nextId), ct);
        if (consumed != 1)
        {
            await RevokeFamilyAsync(current.FamilyId, ct);
            await transaction.CommitAsync(ct);
            return null;
        }
        var nextCredential = NewCredential();
        var next = new RefreshToken { Id = nextId, UserId = current.UserId, FamilyId = current.FamilyId,
            Token = Hash(nextCredential), ExpiresAt = current.ExpiresAt, CreatedAt = Now };
        db.RefreshTokens.Add(next);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return await ResultAsync(current.User, next, nextCredential);
    }

    // Preparing a cookie does not consume its predecessor and cannot issue an access token.
    // The browser must install the cookie before it can present it to CompleteAsync.
    public async Task<RefreshPreparation?> PrepareAsync(string credential, string operation, CancellationToken ct = default)
    {
        if (credential.Length is < 40 or > 256) return null;
        var hash = Hash(credential);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var current = await LockCredentialAsync(hash, ct);
        if (current == null) return null;
        if (current.IsRevoked)
        {
            await RevokeFamilyAsync(current.FamilyId, ct);
            await transaction.CommitAsync(ct);
            return null;
        }
        if (!Guid.TryParseExact(operation, "D", out _)) return null;
        var operationHash = Hash(operation);
        if (current.PreparedFromId.HasValue && current.OperationHash == operationHash && current.PreparationExpiresAt > Now)
        {
            await transaction.CommitAsync(ct);
            return new RefreshPreparation(credential, current.ExpiresAt);
        }
        if (current.IsPending) return null;
        if (await db.RefreshTokens.CountAsync(t => t.FamilyId == current.FamilyId && t.IsPending && t.PreparationExpiresAt > Now, ct) >= 16) return null;

        RefreshToken? pending = current.ReplacedById.HasValue
            ? await db.RefreshTokens.AsNoTracking().SingleOrDefaultAsync(t => t.Id == current.ReplacedById.Value, ct) : null;
        if (pending?.IsPending == true && !pending.IsRevoked && pending.OperationHash == operationHash && pending.PreparationExpiresAt > Now)
        {
            await transaction.CommitAsync(ct);
            return new RefreshPreparation(PreparedCredential(current.Token, operationHash), current.ExpiresAt);
        }
        if (pending?.IsPending == true)
            await db.RefreshTokens.Where(t => t.Id == pending.Id).ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
        var nextCredential = PreparedCredential(current.Token, operationHash);
        // An expired operation cannot be reused to regenerate an identical credential.
        if (await db.RefreshTokens.AnyAsync(t => t.Token == Hash(nextCredential), ct)) return null;
        var next = new RefreshToken { UserId = current.UserId, FamilyId = current.FamilyId, Token = Hash(nextCredential),
            ExpiresAt = current.ExpiresAt, CreatedAt = Now, IsPending = true, PreparedFromId = current.Id,
            OperationHash = operationHash, PreparationExpiresAt = Now.AddSeconds(PreparationSeconds) };
        db.RefreshTokens.Add(next);
        await db.RefreshTokens.Where(t => t.Id == current.Id && !t.IsRevoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ReplacedById, next.Id), ct);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return new RefreshPreparation(nextCredential, next.ExpiresAt);
    }

    public async Task<SessionResult?> CompleteAsync(string credential, string operation, CancellationToken ct = default)
    {
        if (credential.Length is < 40 or > 256) return null;
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var current = await LockCredentialAsync(Hash(credential), ct);
        if (current == null) return null;
        if (current.IsRevoked)
        {
            await RevokeFamilyAsync(current.FamilyId, ct);
            await transaction.CommitAsync(ct);
            return null;
        }
        if (!Guid.TryParseExact(operation, "D", out _)) return null;
        if (!current.PreparedFromId.HasValue || current.OperationHash != Hash(operation) || current.PreparationExpiresAt <= Now) return null;
        if (current.IsPending)
        {
            var consumed = await db.RefreshTokens.Where(t => t.Id == current.PreparedFromId.Value && !t.IsRevoked && t.ReplacedById == current.Id && t.ExpiresAt > Now)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
            if (consumed != 1)
            {
                await RevokeFamilyAsync(current.FamilyId, ct);
                await transaction.CommitAsync(ct);
                return null;
            }
            await db.RefreshTokens.Where(t => t.Id == current.Id).ExecuteUpdateAsync(s => s.SetProperty(t => t.IsPending, false), ct);
        }
        await transaction.CommitAsync(ct);
        // Retrying a lost completion body uses the still-unconsumed successor, never its consumed predecessor.
        return await ResultAsync(current.User, current, credential);
    }

    private async Task<RefreshToken?> LockCredentialAsync(string hash, CancellationToken ct)
    {
        var family = await db.RefreshTokens.Where(t => t.Token == hash).Select(t => (Guid?)t.FamilyId).SingleOrDefaultAsync(ct);
        if (!family.HasValue) return null;
        var locked = await db.SessionFamilies.Where(f => f.Id == family.Value && !f.IsRevoked && f.ExpiresAt > Now)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.UpdatedAt, Now), ct);
        if (locked != 1) return null;
        // Reload after the stable-family lock so concurrent preparation/completion observes committed state.
        var current = await db.RefreshTokens.AsNoTracking().Include(t => t.User).SingleOrDefaultAsync(t => t.Token == hash, ct);
        return current == null || current.ExpiresAt <= Now || current.User.IsDeleted ? null : current;
    }

    private string PreparedCredential(string parentHash, string operationHash)
    {
        var key = SHA256.HashData(Encoding.UTF8.GetBytes("spotibuds-refresh-preparation-v1:" + config.Required("Jwt:Secret")));
        return WebEncoders.Base64UrlEncode(HMACSHA384.HashData(key, Encoding.UTF8.GetBytes(parentHash + ":" + operationHash)));
    }

    private async Task<SessionResult> ResultAsync(User user, RefreshToken session, string credential)
    {
        var roles = await users.GetRolesAsync(user);
        var minutes = Math.Clamp(config.GetValue("Jwt:AccessTokenMinutes", 5), 1, 60);
        var expiry = Now.AddMinutes(minutes);
        var claims = new List<Claim> { new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()), new(ClaimTypes.Name, user.UserName!),
            new("sid", session.FamilyId.ToString()), new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        var jwt = new JwtSecurityToken(config.Required("Jwt:Issuer"), config.Required("Jwt:Audience"), claims,
            notBefore: Now, expires: expiry,
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Required("Jwt:Secret"))), SecurityAlgorithms.HmacSha256));
        return new SessionResult(new JwtSecurityTokenHandler().WriteToken(jwt), credential, session.ExpiresAt, expiry,
            new SessionUser(user.Id, user.UserName!, user.Email!, user.IsPrivate, roles.ToArray()));
    }
}

public record SessionUser(Guid Id, string Username, string Email, bool IsPrivate, string[] Roles);
public record SessionResult(string Token, string Credential, DateTime RefreshExpiresAt, DateTime ExpiresAt, SessionUser User);
public record RefreshPreparation(string Credential, DateTime RefreshExpiresAt);
