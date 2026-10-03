using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Identity.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Identity.Tests;

public class SessionIntegrationTests
{
    private const string Password = "DemoTest!123";
    private static HttpClient Client(IdentityFactory factory)
    {
        var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("X-Spotibuds-Request", "1");
        client.DefaultRequestHeaders.Add("Origin", "http://127.0.0.1:3100");
        return client;
    }
    private static async Task<Guid> Register(HttpClient client, string username)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/register", new { username, email = username + "@spotibuds.local", password = Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        return Guid.Parse(json["userId"]!.GetValue<string>());
    }
    private static async Task<(string Token, string Cookie)> Login(HttpClient client, string username, string password = Password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        var setCookie = response.Headers.GetValues("Set-Cookie").Single();
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Null(json["refreshToken"]);
        return (json["token"]!.GetValue<string>(), setCookie.Split(';')[0]);
    }
    private static HttpRequestMessage Request(HttpMethod method, string path, string? cookie = null, string? token = null, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (cookie != null) request.Headers.Add("Cookie", cookie);
        if (token != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body != null) request.Content = JsonContent.Create(body);
        return request;
    }
    private static HttpRequestMessage RefreshPhase(string phase, string cookie, string? operation)
    {
        var request = Request(HttpMethod.Post, "/api/auth/refresh/" + phase, cookie);
        if (operation != null) request.Headers.Add("X-Spotibuds-Refresh-Request", operation);
        return request;
    }

    [Fact]
    public async Task InterruptedPreparationAndCompletionRecoverWithoutAcceptingConsumedPredecessor()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice"); var operation = Guid.NewGuid().ToString();
        using var prepared = await client.SendAsync(RefreshPhase("prepare", login.Cookie, operation));
        Assert.Equal(HttpStatusCode.NoContent, prepared.StatusCode); Assert.Equal("", await prepared.Content.ReadAsStringAsync());
        var pendingCookie = prepared.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        Assert.NotEqual(login.Cookie, pendingCookie);
        var initial = await factory.InspectAsync(db => db.RefreshTokens.OrderBy(t => t.CreatedAt).ToListAsync());
        Assert.Equal(2, initial.Count); Assert.All(initial, token => Assert.False(token.IsRevoked)); Assert.Single(initial, t => t.IsPending);
        Assert.All(initial, token => Assert.Equal(64, token.Token.Length));
        // Simulate a destroyed document that never applies the prepare response cookie.
        using var retriedPreparation = await client.SendAsync(RefreshPhase("prepare", login.Cookie, operation));
        Assert.Equal(HttpStatusCode.NoContent, retriedPreparation.StatusCode);
        Assert.Equal(pendingCookie, retriedPreparation.Headers.GetValues("Set-Cookie").Single().Split(';')[0]);
        // Cookie already installed but prepare response body lost: preparing the pending cookie is safe.
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(RefreshPhase("prepare", pendingCookie, operation))).StatusCode);
        using var completed = await client.SendAsync(RefreshPhase("complete", pendingCookie, operation));
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode); Assert.False(completed.Headers.Contains("Set-Cookie"));
        // Simulate lost completion body. It retries the unconsumed installed successor, never the predecessor.
        using var recovered = await client.SendAsync(RefreshPhase("complete", pendingCookie, operation));
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode); Assert.False(recovered.Headers.Contains("Set-Cookie"));
        var token = (await recovered.Content.ReadFromJsonAsync<JsonObject>())!["token"]!.GetValue<string>();
        using var repeatPreparation = await client.SendAsync(RefreshPhase("prepare", pendingCookie, operation));
        Assert.Equal(pendingCookie, repeatPreparation.Headers.GetValues("Set-Cookie").Single().Split(';')[0]);
        var final = await factory.InspectAsync(db => db.RefreshTokens.ToListAsync());
        Assert.Equal(2, final.Count); Assert.Single(final, t => !t.IsRevoked); Assert.DoesNotContain(final, t => t.IsPending);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: token))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("prepare", login.Cookie, operation))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("complete", pendingCookie, operation))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: token))).StatusCode);
        Assert.True(await factory.InspectAsync(db => db.SessionFamilies.AllAsync(f => f.IsRevoked)));
        // Missing protocol metadata cannot conceal use of a consumed predecessor.
        var another = await Login(client, "alice"); var anotherOperation = Guid.NewGuid().ToString();
        using var anotherPreparation = await client.SendAsync(RefreshPhase("prepare", another.Cookie, anotherOperation));
        var anotherCookie = anotherPreparation.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(RefreshPhase("complete", anotherCookie, anotherOperation))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("complete", another.Cookie, null))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("complete", anotherCookie, anotherOperation))).StatusCode);
        Assert.True(await factory.InspectAsync(db => db.SessionFamilies.AllAsync(f => f.IsRevoked)));
    }

    [Fact]
    public async Task PreparationCannotAuthenticateAndCompletionRequiresExactOperation()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice"); var operation = Guid.NewGuid().ToString();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("prepare", login.Cookie, null))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("prepare", login.Cookie, "not-a-nonce"))).StatusCode);
        Assert.Equal(1, await factory.InspectAsync(db => db.RefreshTokens.CountAsync()));
        using var prepared = await client.SendAsync(RefreshPhase("prepare", login.Cookie, operation));
        var pendingCookie = prepared.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", pendingCookie))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", pendingCookie))).StatusCode);
        foreach (var incorrect in new[] { null, "invalid", Guid.NewGuid().ToString() })
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("complete", pendingCookie, incorrect))).StatusCode);
        Assert.True(await factory.InspectAsync(db => db.RefreshTokens.AllAsync(t => !t.IsRevoked)));
        Assert.True(await factory.InspectAsync(db => db.RefreshTokens.AnyAsync(t => t.IsPending)));
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(RefreshPhase("complete", pendingCookie, operation))).StatusCode);
    }

    [Fact]
    public async Task PreparationAndCompletionRetryExpireAfterThirtySeconds()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice"); var operation = Guid.NewGuid().ToString();
        using var prepared = await client.SendAsync(RefreshPhase("prepare", login.Cookie, operation));
        var pendingCookie = prepared.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        factory.Clock.Value = factory.Clock.Value.AddSeconds(31);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("complete", pendingCookie, operation))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("prepare", login.Cookie, operation))).StatusCode);
        Assert.True(await factory.InspectAsync(db => db.RefreshTokens.AllAsync(t => !t.IsRevoked)));
        var nextOperation = Guid.NewGuid().ToString();
        using var next = await client.SendAsync(RefreshPhase("prepare", login.Cookie, nextOperation));
        Assert.Equal(HttpStatusCode.NoContent, next.StatusCode);
        var nextCookie = next.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        using var completed = await client.SendAsync(RefreshPhase("complete", nextCookie, nextOperation));
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        factory.Clock.Value = factory.Clock.Value.AddSeconds(31);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(RefreshPhase("complete", nextCookie, nextOperation))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: login.Token))).StatusCode);
        using var nextRotation = await client.SendAsync(RefreshPhase("prepare", nextCookie, Guid.NewGuid().ToString()));
        Assert.Equal(HttpStatusCode.NoContent, nextRotation.StatusCode);
    }

    [Fact]
    public async Task AnonymousAndUnrelatedAdminMutationsHaveNoSideEffects()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        var alice = await Register(client, "alice"); var bob = await Register(client, "bob");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync($"/api/auth/users/{alice}/roles/Admin", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PutAsJsonAsync($"/api/auth/users/{alice}", new { isPrivate = true })).StatusCode);
        var session = await Login(client, "bob");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Request(HttpMethod.Post, $"/api/auth/users/{alice}/roles/Admin", token: session.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Request(HttpMethod.Put, $"/api/auth/users/{alice}", token: session.Token, body: new { isPrivate = true }))).StatusCode);
        Assert.False(await factory.InspectAsync(db => db.Users.Where(u => u.Id == alice).Select(u => u.IsPrivate).SingleAsync()));
        Assert.Single(factory.Sync.Profiles[alice].Roles); Assert.Contains("User", factory.Sync.Profiles[alice].Roles);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Request(HttpMethod.Get, $"/api/auth/users/{alice}", token: session.Token))).StatusCode);
    }

    [Fact]
    public async Task RefreshRequiresOnlyCookieAndHashesAtRestAndReplayRevokesSuccessor()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice");
        var stored = await factory.InspectAsync(db => db.RefreshTokens.Select(t => t.Token).SingleAsync());
        Assert.Equal(64, stored.Length); Assert.False(stored == login.Cookie.Split('=')[1]);
        using var refreshed = await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", login.Cookie));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var nextCookie = refreshed.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        Assert.False(nextCookie == login.Cookie);
        var next = (await refreshed.Content.ReadFromJsonAsync<JsonObject>())!["token"]!.GetValue<string>();
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: next))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", login.Cookie))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", nextCookie))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: next))).StatusCode);
        Assert.Equal(1, await factory.InspectAsync(db => db.SessionFamilies.CountAsync(f => f.IsRevoked)));
    }

    [Fact]
    public async Task LogoutRevokesCurrentFamilyAndAccessTokenImmediately()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice");
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/logout", login.Cookie))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: login.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", login.Cookie))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/auth/logout", null)).StatusCode);
        Assert.All(await factory.InspectAsync(db => db.RefreshTokens.ToListAsync()), t => Assert.True(t.IsRevoked));
    }

    [Fact]
    public async Task PasswordChangeRevokesAllDevices()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var first = await Login(client, "alice"); var second = await Login(client, "alice");
        using var changed = await client.SendAsync(Request(HttpMethod.Post, "/api/auth/change-password", token: first.Token,
            body: new { currentPassword = Password, newPassword = "ChangedDemo!456" }));
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        foreach (var session in new[] { first, second })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: session.Token))).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", session.Cookie))).StatusCode);
        }
        await Login(client, "alice", "ChangedDemo!456");
    }

    [Fact]
    public async Task RecoveryIsGenericSingleUseAndRevokesSessions()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice");
        using var known = await client.PostAsJsonAsync("/api/auth/forgot-password", new { email = "alice@spotibuds.local" });
        using var unknown = await client.PostAsJsonAsync("/api/auth/forgot-password", new { email = "unknown@spotibuds.local" });
        Assert.Equal(HttpStatusCode.OK, known.StatusCode); Assert.Equal(await known.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
        Assert.NotNull(factory.Mailer.Token); Assert.Equal("alice@spotibuds.local", factory.Mailer.Email);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/reset-password", new { email = "alice@spotibuds.local", token = "invalid", password = "ResetDemo!456" })).StatusCode);
        var dto = new { email = "alice@spotibuds.local", token = factory.Mailer.Token, password = "ResetDemo!456" };
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/reset-password", dto)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/reset-password", dto)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: login.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = Password })).StatusCode);
        await Login(client, "alice", "ResetDemo!456");
        Assert.True(await factory.InspectAsync(db => db.PasswordResets.AllAsync(t => t.Used && t.TokenHash.Length == 64)));
    }

    [Fact]
    public async Task ExpiredResetAndRefreshCredentialsAreDenied()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice");
        await client.PostAsJsonAsync("/api/auth/forgot-password", new { email = "alice@spotibuds.local" });
        factory.Clock.Value = factory.Clock.Value.AddMinutes(21);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/reset-password", new { email = "alice@spotibuds.local", token = factory.Mailer.Token, password = "ResetDemo!456" })).StatusCode);
        factory.Clock.Value = factory.Clock.Value.AddDays(8);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", login.Cookie))).StatusCode);
    }

    [Fact]
    public async Task SuccessfulRecoveryInvalidatesEveryOtherOutstandingLink()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        var id = await Register(client, "alice"); var session = await Login(client, "alice");
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/forgot-password", new { email = "alice@spotibuds.local" })).StatusCode);
        var selected = factory.Mailer.Token;
        var other = SessionService.NewCredential();
        // Persist a second outstanding link, as legacy/racing issuance could have left it.
        await factory.InspectAsync(async db =>
        {
            db.PasswordResets.Add(new Identity.Entities.PasswordReset { UserId = id, TokenHash = SessionService.Hash(other),
                ExpiresAt = factory.Clock.Value.UtcDateTime.AddMinutes(20) });
            await db.SaveChangesAsync(); return true;
        });
        Assert.Equal(2, await factory.InspectAsync(db => db.PasswordResets.CountAsync(t => !t.Used)));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/reset-password", new { email = "alice@spotibuds.local", token = selected, password = "ResetDemo!456" })).StatusCode);
        Assert.Equal(0, await factory.InspectAsync(db => db.PasswordResets.CountAsync(t => !t.Used)));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/reset-password", new { email = "alice@spotibuds.local", token = other, password = "OlderLink!789" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: session.Token))).StatusCode);
        await Login(client, "alice", "ResetDemo!456");
    }

    [Fact]
    public async Task SynchronizationOutageIsDurableAndLoginRepairsWithoutDuplicates()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        factory.Sync.Fail = true;
        using var registration = await client.PostAsJsonAsync("/api/auth/register", new { username = "alice", email = "alice@spotibuds.local", password = Password });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, registration.StatusCode);
        Assert.Equal(1, await factory.InspectAsync(db => db.Users.CountAsync()));
        Assert.Equal(1, await factory.InspectAsync(db => db.ProfileSyncWork.CountAsync()));
        Assert.Empty(factory.Sync.Profiles);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = Password })).StatusCode);
        factory.Sync.Fail = false;
        await Login(client, "alice"); await Login(client, "alice");
        Assert.Single(factory.Sync.Profiles);
        Assert.Equal(1, await factory.InspectAsync(db => db.Users.CountAsync()));
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/api/auth/register", new { username = "alice", email = "alice@spotibuds.local", password = Password })).StatusCode);
    }

    [Fact]
    public async Task AdminRoleUpdateSynchronizesAndRevokesOldPrivileges()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        var admin = await Register(client, "admin"); await factory.MakeAdminAsync(admin);
        var alice = await Register(client, "alice"); var aliceSession = await Login(client, "alice"); var adminSession = await Login(client, "admin");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Post, $"/api/auth/users/{alice}/roles/Admin", token: adminSession.Token))).StatusCode);
        Assert.Contains("Admin", factory.Sync.Profiles[alice].Roles);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: aliceSession.Token))).StatusCode);
        var promoted = await Login(client, "alice");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/admins", token: promoted.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(Request(HttpMethod.Post, $"/api/auth/users/{alice}/roles/SuperAdmin", token: adminSession.Token))).StatusCode);
    }

    [Fact]
    public async Task PendingDeletionDisablesAccountAndRetryFinishesCleanup()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        var admin = await Register(client, "admin"); await factory.MakeAdminAsync(admin);
        var alice = await Register(client, "alice"); var aliceSession = await Login(client, "alice"); var adminSession = await Login(client, "admin");
        factory.Sync.Fail = true;
        Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(Request(HttpMethod.Delete, $"/api/auth/users/{alice}", token: adminSession.Token))).StatusCode);
        Assert.True(await factory.InspectAsync(db => db.Users.Where(u => u.Id == alice).Select(u => u.IsDeleted).SingleAsync()));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/me", token: aliceSession.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = Password })).StatusCode);
        factory.Sync.Fail = false;
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(Request(HttpMethod.Delete, $"/api/auth/users/{alice}", token: adminSession.Token))).StatusCode);
        Assert.False(await factory.InspectAsync(db => db.Users.AnyAsync(u => u.Id == alice)));
        Assert.False(factory.Sync.Profiles.ContainsKey(alice));
        Assert.False(await factory.InspectAsync(db => db.ProfileSyncWork.AnyAsync(w => w.UserId == alice)));
    }

    [Fact]
    public async Task OriginAndCustomHeaderProtectionDeniesCookieForgery()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); var login = await Login(client, "alice");
        client.DefaultRequestHeaders.Remove("X-Spotibuds-Request");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", login.Cookie))).StatusCode);
        client.DefaultRequestHeaders.Add("X-Spotibuds-Request", "1"); client.DefaultRequestHeaders.Remove("Origin"); client.DefaultRequestHeaders.Add("Origin", "https://evil.invalid");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Request(HttpMethod.Post, "/api/auth/logout", login.Cookie))).StatusCode);
        Assert.False(await factory.InspectAsync(db => db.SessionFamilies.AnyAsync(f => f.IsRevoked)));
    }

    [Fact]
    public async Task InternalRecoveryRequiresSharedSecretAndDiagnosticRouteIsAbsent()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        var alice = await Register(client, "alice");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"/api/auth/internal/users/{alice}")).StatusCode);
        using var internalRequest = Request(HttpMethod.Get, $"/api/auth/internal/users/{alice}");
        internalRequest.Headers.Add("X-Spotibuds-Service", IdentityFactory.ServiceSecret);
        using var found = await client.SendAsync(internalRequest); Assert.Equal(HttpStatusCode.OK, found.StatusCode);
        Assert.Equal("alice", (await found.Content.ReadFromJsonAsync<JsonObject>())!["username"]!.GetValue<string>());
        var login = await Login(client, "alice");
        Assert.Equal(HttpStatusCode.NotFound, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/test-connection", token: login.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(Request(HttpMethod.Get, "/api/auth/users/search?username=a&pageSize=0", token: login.Token))).StatusCode);
    }

    [Fact]
    public async Task MailOutageReturnsSameFailureForKnownAndUnknownAddresses()
    {
        using var factory = new IdentityFactory(); await factory.InitializeAsync(); using var client = Client(factory);
        await Register(client, "alice"); factory.Mailer.Fail = true;
        foreach (var email in new[] { "alice@spotibuds.local", "unknown@spotibuds.local" })
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.PostAsJsonAsync("/api/auth/forgot-password", new { email })).StatusCode);
        Assert.Equal(0, await factory.InspectAsync(db => db.PasswordResets.CountAsync()));
    }
}
