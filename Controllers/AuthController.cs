using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Identity.Data;
using Identity.Entities;
using Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Identity.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(UserManager<User> users, RoleManager<IdentityRole<Guid>> roles,
    SignInManager<User> signIn, IdentityDbContext db, SessionService sessions, ProfileReconciler profiles,
    IRecoveryMailer mailer, IConfiguration config, TimeProvider clock, IWebHostEnvironment environment) : ControllerBase
{
    private Guid Actor => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    private const string RecoveryMessage = "If the account exists, a password reset message has been sent to the local inbox.";

    private bool BrowserRequestAllowed() => Request.Headers["X-Spotibuds-Request"] == "1" &&
        (!Request.Headers.TryGetValue("Origin", out var origin) || config.Required("Cors:AllowedOrigins")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Contains(origin.ToString(), StringComparer.Ordinal));

    private bool ServiceAllowed()
    {
        var presented = Request.Headers["X-Spotibuds-Service"].ToString();
        var expected = config.Required("ServiceAuth:Secret");
        return presented.Length == expected.Length && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presented), Encoding.UTF8.GetBytes(expected));
    }

    private void SetCookie(string credential, DateTime expiresAt) => Response.Cookies.Append(SessionService.CookieName, credential,
        new CookieOptions { HttpOnly = true, Secure = !environment.IsDevelopment() && !environment.IsEnvironment("Test") || Request.IsHttps, SameSite = SameSiteMode.Strict,
            Path = "/api/auth", Expires = new DateTimeOffset(expiresAt), IsEssential = true });

    private void ClearCookie() => Response.Cookies.Delete(SessionService.CookieName,
        new CookieOptions { HttpOnly = true, Secure = !environment.IsDevelopment() && !environment.IsEnvironment("Test") || Request.IsHttps, SameSite = SameSiteMode.Strict, Path = "/api/auth" });

    private IActionResult SessionResponse(SessionResult session, bool setCookie = true)
    {
        if (setCookie) SetCookie(session.Credential, session.RefreshExpiresAt);
        Response.Headers.CacheControl = "no-store";
        return Ok(new { session.Token, session.User, session.ExpiresAt });
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("register")]
    public Task<IActionResult> Register(RegisterDto dto, CancellationToken ct) => RegisterCore(dto, "User", ct);

    [Authorize(Roles = "Admin")]
    [HttpPost("create-admin")]
    public Task<IActionResult> CreateAdmin(RegisterDto dto, CancellationToken ct) => RegisterCore(dto, "Admin", ct);

    private async Task<IActionResult> RegisterCore(RegisterDto dto, string role, CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        if (await users.FindByNameAsync(dto.Username.Trim()) != null || await users.FindByEmailAsync(dto.Email.Trim()) != null)
            return Conflict(new { message = "Username or email is already registered" });
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var user = new User { UserName = dto.Username.Trim(), Email = dto.Email.Trim(), IsPrivate = dto.IsPrivate ?? false,
            CreatedAt = clock.GetUtcNow().UtcDateTime, LockoutEnabled = true };
        var result = await users.CreateAsync(user, dto.Password);
        if (!result.Succeeded) return BadRequest(new { message = "Account could not be created", errors = result.Errors.Select(e => e.Description) });
        result = await users.AddToRoleAsync(user, role);
        if (!result.Succeeded) return BadRequest(new { message = "Account role could not be assigned" });
        await profiles.EnqueueAsync(user.Id, ct: ct);
        await tx.CommitAsync(ct);
        if (!await profiles.ReconcileAsync(user.Id, ct)) return StatusCode(503, new { message = "Your account was created; profile setup is pending. Retry login shortly.", userId = user.Id, pending = true });
        return Ok(new { message = "Account created", userId = user.Id });
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto, CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        var user = await users.FindByNameAsync(dto.Username.Trim()) ?? await users.FindByEmailAsync(dto.Username.Trim());
        if (user == null || user.IsDeleted) return Unauthorized(new { message = "Invalid username or password" });
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        if (user.IsDeleted) return Unauthorized(new { message = "Invalid username or password" });
        var checkedPassword = await signIn.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: true);
        if (!checkedPassword.Succeeded) { await tx.CommitAsync(ct); return Unauthorized(new { message = "Invalid username or password, or account temporarily locked" }); }
        // Idempotent repair also covers a profile removed outside normal application paths.
        await profiles.EnqueueAsync(user.Id, ct: ct);
        if (!await profiles.ReconcileAsync(user.Id, ct)) { await tx.CommitAsync(ct); return StatusCode(503, new { message = "Profile setup is pending. Retry login shortly." }); }
        if (Request.Cookies.TryGetValue(SessionService.CookieName, out var old)) await sessions.RevokeCredentialAsync(old, ct);
        var session = await sessions.CreateAsync(user, ct: ct);
        await tx.CommitAsync(ct);
        return SessionResponse(session);
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        if (!Request.Cookies.TryGetValue(SessionService.CookieName, out var credential)) return Unauthorized(new { message = "Refresh session missing" });
        var result = await sessions.RotateAsync(credential, ct);
        if (result == null) { ClearCookie(); return Unauthorized(new { message = "Refresh session expired, revoked, or replayed" }); }
        return SessionResponse(result);
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("refresh/prepare")]
    public async Task<IActionResult> PrepareRefresh(CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        if (!Request.Cookies.TryGetValue(SessionService.CookieName, out var credential)) return Unauthorized();
        var result = await sessions.PrepareAsync(credential, Request.Headers["X-Spotibuds-Refresh-Request"].ToString(), ct);
        if (result == null) { ClearCookie(); return Unauthorized(new { message = "Refresh preparation expired, revoked, or invalid" }); }
        SetCookie(result.Credential, result.RefreshExpiresAt);
        Response.Headers.CacheControl = "no-store";
        return NoContent();
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("refresh/complete")]
    public async Task<IActionResult> CompleteRefresh(CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        if (!Request.Cookies.TryGetValue(SessionService.CookieName, out var credential)) return Unauthorized();
        var result = await sessions.CompleteAsync(credential, Request.Headers["X-Spotibuds-Refresh-Request"].ToString(), ct);
        if (result == null) { ClearCookie(); return Unauthorized(new { message = "Refresh completion expired, revoked, or invalid" }); }
        return SessionResponse(result, setCookie: false);
    }

    [AllowAnonymous]
    [HttpPost("logout"), HttpPost("revoke")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        if (Request.Cookies.TryGetValue(SessionService.CookieName, out var credential)) await sessions.RevokeCredentialAsync(credential, ct);
        ClearCookie();
        return NoContent();
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var user = await users.FindByIdAsync(Actor.ToString());
        if (user == null || user.IsDeleted) return Unauthorized();
        return Ok(new SessionUser(user.Id, user.UserName!, user.Email!, user.IsPrivate, (await users.GetRolesAsync(user)).ToArray()));
    }

    [HttpPut("me")]
    public Task<IActionResult> UpdateMe(UpdateUserDto dto, CancellationToken ct) => UpdateAccount(Actor, dto, ct);

    [Authorize(Roles = "Admin")]
    [HttpPut("users/{id:guid}")]
    public Task<IActionResult> UpdateUser(Guid id, UpdateUserDto dto, CancellationToken ct) => UpdateAccount(id, dto, ct);

    private async Task<IActionResult> UpdateAccount(Guid id, UpdateUserDto dto, CancellationToken ct)
    {
        var user = await users.FindByIdAsync(id.ToString());
        if (user == null || user.IsDeleted) return NotFound();
        // External email verification is outside this local demo. An email change is intentionally unavailable.
        if (dto.Email != null && !StringComparer.OrdinalIgnoreCase.Equals(dto.Email.Trim(), user.Email))
            return BadRequest(new { message = "Email changes require verification and are unavailable in the local demo" });
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        if (user.IsDeleted) return NotFound();
        if (dto.IsPrivate.HasValue) user.IsPrivate = dto.IsPrivate.Value;
        var result = await users.UpdateAsync(user);
        if (!result.Succeeded) return BadRequest(new { message = "Account update failed", errors = result.Errors.Select(e => e.Description) });
        await profiles.EnqueueAsync(id, ct: ct);
        await tx.CommitAsync(ct);
        if (!await profiles.ReconcileAsync(id, ct)) return StatusCode(503, new { message = "Account updated; profile synchronization is pending", pending = true });
        return Ok(new { message = "Account updated" });
    }

    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordDto dto, CancellationToken ct)
    {
        var user = await users.FindByIdAsync(Actor.ToString());
        if (user == null) return Unauthorized();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        var result = await users.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
        if (!result.Succeeded) return BadRequest(new { message = "Password change failed", errors = result.Errors.Select(e => e.Description) });
        await sessions.RevokeUserAsync(user.Id, ct);
        await db.PasswordResets.Where(t => t.UserId == user.Id && !t.Used).ExecuteUpdateAsync(s => s.SetProperty(t => t.Used, true), ct);
        await tx.CommitAsync(ct);
        ClearCookie();
        return Ok(new { message = "Password changed. Sign in again." });
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("users/{id:guid}/roles/{role}")]
    public Task<IActionResult> AssignRole(Guid id, string role, CancellationToken ct) => ChangeRole(id, role, ct);
    [Authorize(Roles = "Admin")]
    [HttpPost("users/{id:guid}/promote-to-admin")]
    public Task<IActionResult> Promote(Guid id, CancellationToken ct) => ChangeRole(id, "Admin", ct);
    [Authorize(Roles = "Admin")]
    [HttpPost("users/{id:guid}/demote-to-user")]
    public Task<IActionResult> Demote(Guid id, CancellationToken ct) => ChangeRole(id, "User", ct);

    private async Task<IActionResult> ChangeRole(Guid id, string role, CancellationToken ct)
    {
        if (role is not ("Admin" or "Musician" or "User") || !await roles.RoleExistsAsync(role)) return BadRequest(new { message = "Unknown role" });
        if (id == Actor && role != "Admin") return Conflict(new { message = "Administrators cannot demote themselves" });
        var user = await users.FindByIdAsync(id.ToString());
        if (user == null || user.IsDeleted) return NotFound();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        if (user.IsDeleted) return NotFound();
        var current = await users.GetRolesAsync(user);
        var remove = await users.RemoveFromRolesAsync(user, current);
        var add = remove.Succeeded ? await users.AddToRoleAsync(user, role) : remove;
        if (!add.Succeeded) return BadRequest(new { message = "Role change failed" });
        await sessions.RevokeUserAsync(id, ct);
        await profiles.EnqueueAsync(id, ct: ct);
        await tx.CommitAsync(ct);
        if (!await profiles.ReconcileAsync(id, ct)) return StatusCode(503, new { message = "Role changed; profile synchronization is pending", pending = true });
        return Ok(new { message = "Role changed. The account must sign in again." });
    }

    [HttpGet("users/{id:guid}")]
    public async Task<IActionResult> GetUser(Guid id)
    {
        if (id != Actor && !User.IsInRole("Admin")) return Forbid();
        var user = await users.FindByIdAsync(id.ToString());
        return user == null || user.IsDeleted ? NotFound() : Ok(await UserContract(user));
    }

    [Authorize(Roles = "Admin")]
    [HttpDelete("users/{id:guid}")]
    public async Task<IActionResult> DeleteUser(Guid id, CancellationToken ct)
    {
        if (id == Actor) return Conflict(new { message = "Administrators cannot delete themselves" });
        var user = await users.FindByIdAsync(id.ToString());
        if (user == null) return NoContent();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        user.IsDeleted = true;
        await db.SaveChangesAsync(ct);
        await sessions.RevokeUserAsync(id, ct);
        await profiles.EnqueueAsync(id, delete: true, ct);
        await tx.CommitAsync(ct);
        if (!await profiles.ReconcileAsync(id, ct)) return Accepted(new { message = "Account disabled; cleanup is pending", pending = true });
        return NoContent();
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("users")]
    public Task<IActionResult> AllUsers(int page = 1, int pageSize = 50, CancellationToken ct = default) => ListUsers(null, page, pageSize, ct);
    [Authorize(Roles = "Admin")]
    [HttpGet("admins")]
    public Task<IActionResult> Admins(int page = 1, int pageSize = 50, CancellationToken ct = default) => ListUsers("Admin", page, pageSize, ct);

    private async Task<IActionResult> ListUsers(string? role, int page, int pageSize, CancellationToken ct)
    {
        if (page < 1 || page > 10000 || pageSize < 1 || pageSize > 100) return BadRequest(new { message = "Invalid pagination" });
        var query = db.Users.Where(u => !u.IsDeleted);
        if (role != null) query = query.Where(u => db.UserRoles.Any(ur => ur.UserId == u.Id && db.Roles.Any(r => r.Id == ur.RoleId && r.Name == role)));
        var count = await query.CountAsync(ct);
        var found = await query.OrderBy(u => u.UserName).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        var ids = found.Select(u => u.Id).ToList();
        var assignments = await (from ur in db.UserRoles join r in db.Roles on ur.RoleId equals r.Id where ids.Contains(ur.UserId) select new { ur.UserId, r.Name }).ToListAsync(ct);
        return Ok(new { users = found.Select(u => new { u.Id, username = u.UserName, u.Email, u.IsPrivate, u.CreatedAt,
            roles = assignments.Where(a => a.UserId == u.Id).Select(a => a.Name).ToArray() }), totalCount = count, page, pageSize });
    }

    [HttpGet("users/search")]
    public async Task<IActionResult> Search(string username = "", int page = 1, int pageSize = 10, CancellationToken ct = default)
    {
        if (username.Length > 50 || page < 1 || page > 1000 || pageSize is < 1 or > 50) return BadRequest(new { message = "Invalid search or pagination" });
        if (string.IsNullOrWhiteSpace(username)) return Ok(new { users = Array.Empty<object>(), page, pageSize });
        var found = await db.Users.Where(u => !u.IsDeleted && (!u.IsPrivate || u.Id == Actor) && u.UserName!.Contains(username))
            .OrderBy(u => u.UserName).Skip((page - 1) * pageSize).Take(pageSize).Select(u => new { u.Id, username = u.UserName, u.IsPrivate }).ToListAsync(ct);
        return Ok(new { users = found, page, pageSize });
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> Forgot(ForgotPasswordDto dto, CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        // Check the local sink for both known and unknown addresses, so an outage does not enumerate accounts.
        if (!config.GetValue("Smtp:Enabled", true))
            return StatusCode(503, new { message = "Password reset email is not configured yet. Contact the site owner for help signing in." });
        await mailer.CheckAvailableAsync(ct);
        var user = await users.FindByEmailAsync(dto.Email.Trim());
        if (user != null && !user.IsDeleted)
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await LockAccount(user, ct);
            if (user.IsDeleted) return Ok(new { message = RecoveryMessage });
            var credential = SessionService.NewCredential();
            await db.PasswordResets.Where(t => t.UserId == user.Id && !t.Used).ExecuteUpdateAsync(s => s.SetProperty(t => t.Used, true), ct);
            db.PasswordResets.Add(new PasswordReset { UserId = user.Id, TokenHash = SessionService.Hash(credential), ExpiresAt = clock.GetUtcNow().UtcDateTime.AddMinutes(20) });
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            await mailer.SendAsync(user.Email!, credential, ct);
        }
        return Ok(new { message = RecoveryMessage });
    }

    [AllowAnonymous, EnableRateLimiting("auth")]
    [HttpPost("reset-password")]
    public async Task<IActionResult> Reset(ResetPasswordDto dto, CancellationToken ct)
    {
        if (!BrowserRequestAllowed()) return StatusCode(403, new { message = "Untrusted request origin or missing request header" });
        var user = await users.FindByEmailAsync(dto.Email.Trim());
        var invalid = new { message = "Reset link is invalid, expired, or already used" };
        if (user == null || user.IsDeleted) return BadRequest(invalid);
        var validation = new List<IdentityError>();
        foreach (var validator in users.PasswordValidators)
        {
            var checkedPassword = await validator.ValidateAsync(users, user, dto.Password);
            validation.AddRange(checkedPassword.Errors);
        }
        if (validation.Count != 0) return BadRequest(new { message = "Password does not meet requirements", errors = validation.Select(e => e.Description) });
        var hash = SessionService.Hash(dto.Token);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        if (user.IsDeleted) return BadRequest(invalid);
        var used = await db.PasswordResets.Where(t => t.UserId == user.Id && t.TokenHash == hash && !t.Used && t.ExpiresAt > clock.GetUtcNow().UtcDateTime)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Used, true), ct);
        if (used != 1) return BadRequest(invalid);
        await db.PasswordResets.Where(t => t.UserId == user.Id && !t.Used)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Used, true), ct);
        user.PasswordHash = users.PasswordHasher.HashPassword(user, dto.Password);
        var update = await users.UpdateSecurityStampAsync(user);
        if (!update.Succeeded) return StatusCode(503, new { message = "Password reset could not be saved" });
        await sessions.RevokeUserAsync(user.Id, ct);
        await tx.CommitAsync(ct);
        ClearCookie();
        return Ok(new { message = "Password reset. Sign in with your new password." });
    }

    private async Task<object> UserContract(User user) => new { user.Id, username = user.UserName, user.Email, user.IsPrivate, user.CreatedAt, roles = await users.GetRolesAsync(user) };

    private async Task LockAccount(User user, CancellationToken ct)
    {
        // A no-op conditional UPDATE takes the stable PostgreSQL row lock. Login cannot
        // issue a session with a password/role snapshot that changed during authentication.
        await db.Users.Where(u => u.Id == user.Id).ExecuteUpdateAsync(s => s.SetProperty(u => u.ConcurrencyStamp, u => u.ConcurrencyStamp), ct);
        await db.Entry(user).ReloadAsync(ct);
    }

    [AllowAnonymous]
    [HttpGet("internal/sessions/{sid:guid}")]
    public async Task<IActionResult> ValidateSession(Guid sid, CancellationToken ct)
    {
        if (!ServiceAllowed()) return Unauthorized();
        return await sessions.IsActiveAsync(sid, ct) ? NoContent() : Unauthorized();
    }

    [AllowAnonymous]
    [HttpGet("internal/users/{id:guid}")]
    public async Task<IActionResult> InternalUser(Guid id)
    {
        if (!ServiceAllowed()) return Unauthorized();
        var user = await users.FindByIdAsync(id.ToString());
        return user == null || user.IsDeleted ? NotFound() : Ok(await UserContract(user));
    }

    [AllowAnonymous]
    [HttpGet("internal/users")]
    public Task<IActionResult> InternalUsers(int page = 1, int pageSize = 100, CancellationToken ct = default) =>
        ServiceAllowed() ? ListUsers(null, page, pageSize, ct) : Task.FromResult<IActionResult>(Unauthorized());

    [AllowAnonymous]
    [HttpPost("internal/profile")]
    public async Task<IActionResult> InternalProfile(InternalProfileDto dto, CancellationToken ct)
    {
        if (!ServiceAllowed()) return Unauthorized();
        var user = await users.FindByIdAsync(dto.IdentityUserId.ToString());
        if (user == null || user.IsDeleted) return NotFound();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LockAccount(user, ct);
        if (user.IsDeleted) return NotFound();
        if (dto.UserName != null) user.UserName = dto.UserName.Trim();
        if (dto.IsPrivate.HasValue) user.IsPrivate = dto.IsPrivate.Value;
        var result = await users.UpdateAsync(user);
        if (!result.Succeeded) return Conflict(new { message = "Account fields could not be updated", errors = result.Errors.Select(e => e.Description) });
        await profiles.EnqueueAsync(user.Id, ct: ct);
        await tx.CommitAsync(ct);
        if (!await profiles.ReconcileAsync(user.Id, ct)) return StatusCode(503, new { message = "Account updated; profile synchronization pending", pending = true });
        return Ok(await UserContract(user));
    }
}

public class RegisterDto
{
    [Required, StringLength(50, MinimumLength = 3), RegularExpression("^[a-zA-Z0-9_.-]+$")]
    public string Username { get; set; } = "";
    [Required, EmailAddress, StringLength(100)] public string Email { get; set; } = "";
    [Required, StringLength(100, MinimumLength = 8)] public string Password { get; set; } = "";
    [StringLength(100)] public string? Name { get; set; }
    public bool? IsPrivate { get; set; }
}
public class LoginDto
{
    [Required, StringLength(100)] public string Username { get; set; } = "";
    [Required, StringLength(100)] public string Password { get; set; } = "";
    public bool RememberMe { get; set; }
}
public class UpdateUserDto
{
    [EmailAddress, StringLength(100)] public string? Email { get; set; }
    public bool? IsPrivate { get; set; }
}
public class ChangePasswordDto
{
    [Required, StringLength(100)] public string CurrentPassword { get; set; } = "";
    [Required, StringLength(100, MinimumLength = 8)] public string NewPassword { get; set; } = "";
}
public class ForgotPasswordDto
{
    [Required, EmailAddress, StringLength(100)] public string Email { get; set; } = "";
}
public class ResetPasswordDto : ForgotPasswordDto
{
    [Required, StringLength(256)] public string Token { get; set; } = "";
    [Required, StringLength(100, MinimumLength = 8)] public string Password { get; set; } = "";
}
public class InternalProfileDto
{
    [Required] public Guid IdentityUserId { get; set; }
    [StringLength(50, MinimumLength = 3), RegularExpression("^[a-zA-Z0-9_.-]+$")] public string? UserName { get; set; }
    public bool? IsPrivate { get; set; }
}
