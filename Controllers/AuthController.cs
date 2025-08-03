using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Identity.Entities;
using Identity.Services;
using Identity.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Text.Json.Serialization;

namespace Identity.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly IConfiguration _configuration;
    private readonly IUserSyncService _userSyncService;
    private readonly ILogger<AuthController> _logger;
    private readonly IdentityDbContext _dbContext;

    public AuthController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        IConfiguration configuration,
        IUserSyncService userSyncService,
        ILogger<AuthController> logger,
        IdentityDbContext dbContext)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _configuration = configuration;
        _userSyncService = userSyncService;
        _logger = logger;
        _dbContext = dbContext;
    }

    private async Task<string> GenerateJwtTokenAsync(User user)
    {
        var roles = await _userManager.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var jwtSection = _configuration.GetSection("Jwt");
        var secret = jwtSection["Secret"];

        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new InvalidOperationException("JWT secret key is not configured");
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expirationMinutes = jwtSection.GetValue<int>("ExpirationMinutes", 60);
        var token = new JwtSecurityToken(
            issuer: jwtSection["Issuer"],
            audience: jwtSection["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private async Task<RefreshToken> CreateRefreshTokenAsync(User user)
    {
        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = GenerateRefreshToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(7), // 7 days expiration
            CreatedAt = DateTime.UtcNow
        };

        _dbContext.RefreshTokens.Add(refreshToken);
        await _dbContext.SaveChangesAsync();

        return refreshToken;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            _logger.LogInformation("Registration attempt for user: {Username}, Email: {Email}", dto.Username, dto.Email);

            // Test database connectivity before proceeding
            var dbCheckStart = DateTime.UtcNow;
            try
            {
                await _dbContext.Database.CanConnectAsync();
                var dbCheckTime = DateTime.UtcNow - dbCheckStart;
                _logger.LogInformation("Database connectivity check completed in {DbCheckTime}ms", dbCheckTime.TotalMilliseconds);
            }
            catch (Exception dbEx)
            {
                var dbCheckTime = DateTime.UtcNow - dbCheckStart;
                _logger.LogError(dbEx, "Database connectivity check failed during registration after {DbCheckTime}ms", dbCheckTime.TotalMilliseconds);
                return StatusCode(500, new { message = "Database temporarily unavailable. Please try again later.", detail = "Database connection failed" });
            }

            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
            {
                _logger.LogWarning("Registration failed: Email {Email} already exists", dto.Email);
                return BadRequest(new { message = "User with this email already exists" });
            }

            existingUser = await _userManager.FindByNameAsync(dto.Username);
            if (existingUser != null)
            {
                _logger.LogWarning("Registration failed: Username {Username} already taken", dto.Username);
                return BadRequest(new { message = "Username is already taken" });
            }

            var user = new User
            {
                UserName = dto.Username,
                Email = dto.Email,
                IsPrivate = dto.IsPrivate ?? false,
                CreatedAt = DateTime.UtcNow
            };

            var userCreateStart = DateTime.UtcNow;
            _logger.LogInformation("Creating user {Username} with Identity", dto.Username);
            var result = await _userManager.CreateAsync(user, dto.Password);
            var userCreateTime = DateTime.UtcNow - userCreateStart;
            _logger.LogInformation("User creation completed in {UserCreateTime}ms", userCreateTime.TotalMilliseconds);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {UserId} created successfully in Identity, adding to User role", user.Id);
                
                // Add user to role with error handling
                var roleAddStart = DateTime.UtcNow;
                try
                {
                    await _userManager.AddToRoleAsync(user, "User");
                    var roleAddTime = DateTime.UtcNow - roleAddStart;
                    _logger.LogInformation("User {UserId} added to User role successfully in {RoleAddTime}ms", user.Id, roleAddTime.TotalMilliseconds);
                }
                catch (Exception roleEx)
                {
                    var roleAddTime = DateTime.UtcNow - roleAddStart;
                    _logger.LogError(roleEx, "Failed to add user {UserId} to User role after {RoleAddTime}ms, but registration will continue", user.Id, roleAddTime.TotalMilliseconds);
                }
                
                // Sync to MongoDB - this is required for the system to work properly
                var mongoSyncStart = DateTime.UtcNow;
                try
                {
                    _logger.LogInformation("Syncing user {UserId} to MongoDB", user.Id);
                    
                    // Add timeout for MongoDB sync operation
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15)); // Reduced from 20 to 15 seconds
                    await _userSyncService.SyncUserToMongoDbAsync(user, cts.Token);
                    var mongoSyncTime = DateTime.UtcNow - mongoSyncStart;
                    _logger.LogInformation("User {UserId} synced to MongoDB successfully in {MongoSyncTime}ms", user.Id, mongoSyncTime.TotalMilliseconds);
                }
                catch (OperationCanceledException)
                {
                    var mongoSyncTime = DateTime.UtcNow - mongoSyncStart;
                    _logger.LogError("MongoDB sync timeout for user {UserId} during registration after {MongoSyncTime}ms", user.Id, mongoSyncTime.TotalMilliseconds);
                    
                    // MongoDB sync timeout - clean up the Identity user
                    try
                    {
                        await _userManager.DeleteAsync(user);
                        _logger.LogInformation("Cleaned up Identity user {UserId} due to MongoDB sync timeout", user.Id);
                    }
                    catch (Exception cleanupEx)
                    {
                        _logger.LogError(cleanupEx, "Failed to clean up Identity user {UserId} after MongoDB sync timeout", user.Id);
                    }
                    
                    return StatusCode(500, new { message = "User registration failed due to database synchronization timeout. Please try again.", detail = "MongoDB sync operation timed out" });
                }
                catch (Exception ex)
                {
                    var mongoSyncTime = DateTime.UtcNow - mongoSyncStart;
                    _logger.LogError(ex, "Failed to sync user {UserId} to MongoDB during registration after {MongoSyncTime}ms", user.Id, mongoSyncTime.TotalMilliseconds);
                    
                    // MongoDB sync failure is critical - we should clean up the Identity user
                    try
                    {
                        await _userManager.DeleteAsync(user);
                        _logger.LogInformation("Cleaned up Identity user {UserId} due to MongoDB sync failure", user.Id);
                    }
                    catch (Exception cleanupEx)
                    {
                        _logger.LogError(cleanupEx, "Failed to clean up Identity user {UserId} after MongoDB sync failure", user.Id);
                    }
                    
                    return StatusCode(500, new { message = "User registration failed due to database synchronization error", detail = ex.Message });
                }

                var totalTime = DateTime.UtcNow - startTime;
                _logger.LogInformation("User {UserId} registered successfully in {TotalTime}ms", user.Id, totalTime.TotalMilliseconds);
                return Ok(new { message = "User registered successfully", userId = user.Id });
            }

            // Log specific validation errors
            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("User registration failed for {Username}: {Errors}", dto.Username, string.Join(", ", errors));
            return BadRequest(new { message = "Registration failed", errors = errors });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during user registration for {Username}: {Error}", dto.Username, ex.Message);
            
            // Log stack trace for debugging
            _logger.LogError("Stack trace: {StackTrace}", ex.StackTrace);
            
            // Check if it's a database-related exception
            if (ex.Message.Contains("transient") || ex.Message.Contains("connection") || ex.Message.Contains("timeout"))
            {
                return StatusCode(500, new { message = "Database temporarily unavailable. Please try again in a moment.", detail = "Transient database error" });
            }
            
            return StatusCode(500, new { message = "An error occurred during registration", detail = ex.Message });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        try
        {
            var user = await _userManager.FindByNameAsync(dto.Username);
            if (user == null)
            {
                return BadRequest(new { message = "Invalid credentials" });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                return BadRequest(new { message = $"Account locked until {lockoutEnd}" });
            }

            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Invalid credentials" });
            }

            var jwtToken = await GenerateJwtTokenAsync(user);
            var refreshToken = await CreateRefreshTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            _logger.LogInformation("User {UserId} logged in successfully", user.Id);

            return Ok(new
            {
                message = "Login successful",
                token = jwtToken,
                refreshToken = refreshToken.Token,
                user = new {
                    id = user.Id,
                    username = user.UserName,
                    email = user.Email,
                    isPrivate = user.IsPrivate,
                    createdAt = user.CreatedAt,
                    roles = roles
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user login");
            return StatusCode(500, new { message = "An error occurred during login" });
        }
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok(new { message = "Logged out successfully" });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                isPrivate = user.IsPrivate,
                createdAt = user.CreatedAt,
                roles = roles
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user");
            return StatusCode(500, new { message = "An error occurred" });
        }
    }

    [Authorize]
    [HttpPut("me")]
    public async Task<IActionResult> UpdateCurrentUser([FromBody] UpdateUserDto dto)
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            if (!string.IsNullOrEmpty(dto.Email) && dto.Email != user.Email)
            {
                var existingUser = await _userManager.FindByEmailAsync(dto.Email);
                if (existingUser != null && existingUser.Id != user.Id)
                {
                    return BadRequest(new { message = "Email is already in use" });
                }
                user.Email = dto.Email;
            }

            if (dto.IsPrivate.HasValue)
            {
                user.IsPrivate = dto.IsPrivate.Value;
            }

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                try
                {
                    await _userSyncService.UpdateUserInMongoDbAsync(user);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to sync user {UserId} to MongoDB during update", user.Id);
                }

                _logger.LogInformation("User {UserId} updated successfully", user.Id);
                return Ok(new { message = "User updated successfully" });
            }

            return BadRequest(new { message = "Update failed", errors = result.Errors.Select(e => e.Description) });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user");
            return StatusCode(500, new { message = "An error occurred during update" });
        }
    }

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation("User {UserId} changed password successfully", user.Id);
                return Ok(new { message = "Password changed successfully" });
            }

            return BadRequest(new { message = "Password change failed", errors = result.Errors.Select(e => e.Description) });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error changing password");
            return StatusCode(500, new { message = "An error occurred during password change" });
        }
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("users/{id}/roles/{role}")]
    public async Task<IActionResult> AssignRole(Guid id, string role)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return NotFound("User not found");
            }

            if (!await _roleManager.RoleExistsAsync(role))
            {
                return BadRequest("Role does not exist");
            }

            if (await _userManager.IsInRoleAsync(user, role))
            {
                return BadRequest("User already has this role");
            }

            var result = await _userManager.AddToRoleAsync(user, role);
            if (result.Succeeded)
            {
                _logger.LogInformation("Role {Role} assigned to user {UserId}", role, user.Id);
                return Ok(new { message = $"Role '{role}' assigned successfully" });
            }

            return BadRequest(new { message = "Role assignment failed", errors = result.Errors.Select(e => e.Description) });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning role");
            return StatusCode(500, new { message = "An error occurred during role assignment" });
        }
    }

    [Authorize]
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(Guid id)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return NotFound();
            }

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                isPrivate = user.IsPrivate,
                createdAt = user.CreatedAt,
                roles = roles
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user {UserId}", id);
            return StatusCode(500, new { message = "An error occurred while retrieving user" });
        }
    }

    [Authorize(Roles = "Admin")]
    [HttpPut("users/{id}")]
    public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserDto dto)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return NotFound();
            }

            if (!string.IsNullOrEmpty(dto.Email) && dto.Email != user.Email)
            {
                var existingUser = await _userManager.FindByEmailAsync(dto.Email);
                if (existingUser != null && existingUser.Id != user.Id)
                {
                    return BadRequest(new { message = "Email is already in use" });
                }
                user.Email = dto.Email;
            }

            if (dto.IsPrivate.HasValue)
            {
                user.IsPrivate = dto.IsPrivate.Value;
            }

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                try
                {
                    await _userSyncService.UpdateUserInMongoDbAsync(user);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to sync user {UserId} to MongoDB during admin update", user.Id);
                }

                _logger.LogInformation("User {UserId} updated successfully by admin", user.Id);
                return Ok(new { message = "User updated successfully" });
            }

            return BadRequest(new { message = "Update failed", errors = result.Errors.Select(e => e.Description) });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user {UserId}", id);
            return StatusCode(500, new { message = "An error occurred during update" });
        }
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto dto)
    {
        try
        {
            var refreshToken = await _dbContext.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == dto.RefreshToken);

            if (refreshToken == null || refreshToken.IsRevoked || refreshToken.ExpiresAt <= DateTime.UtcNow)
            {
                return BadRequest(new { message = "Invalid or expired refresh token" });
            }

            var user = refreshToken.User;
            var jwtToken = await GenerateJwtTokenAsync(user);
            var newRefreshToken = await CreateRefreshTokenAsync(user);

            refreshToken.IsRevoked = true;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Token refreshed for user {UserId}", user.Id);

            return Ok(new
            {
                message = "Token refreshed successfully",
                token = jwtToken,
                refreshToken = newRefreshToken.Token
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return StatusCode(500, new { message = "An error occurred during token refresh" });
        }
    }

    [Authorize]
    [HttpPost("revoke")]
    public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenDto dto)
    {
        try
        {
            var refreshToken = await _dbContext.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == dto.RefreshToken);

            if (refreshToken == null)
            {
                return BadRequest(new { message = "Invalid refresh token" });
            }

            refreshToken.IsRevoked = true;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Refresh token revoked for user {UserId}", refreshToken.UserId);

            return Ok(new { message = "Refresh token revoked successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking refresh token");
            return StatusCode(500, new { message = "An error occurred during token revocation" });
        }
    }

    [Authorize]
    [HttpGet("users/search")]
    public async Task<IActionResult> SearchUsers([FromQuery] string username, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return BadRequest("Username parameter is required");
            }

            if (pageSize > 50)
            {
                pageSize = 50;
            }

            var users = await _userManager.Users
                .Where(u => u.UserName!.Contains(username))
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(u => new
                {
                    id = u.Id,
                    username = u.UserName,
                    isPrivate = u.IsPrivate
                })
                .ToListAsync();

            return Ok(new { users, page, pageSize });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching users");
            return StatusCode(500, new { message = "An error occurred during search" });
        }
    }

    [HttpGet("test-connection")]
    public async Task<IActionResult> TestDatabaseConnection()
    {
        try
        {
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            _logger.LogInformation("Testing connection with: {ConnectionString}", connectionString?.Substring(0, Math.Min(50, connectionString?.Length ?? 0)) + "...");
            
            // Test database context
            var canConnect = await _dbContext.Database.CanConnectAsync();
            
            // Test MongoDB connection
            var mongoConnectionString = _configuration.GetConnectionString("MongoDb");
            
            return Ok(new
            {
                timestamp = DateTime.UtcNow,
                postgresql = new
                {
                    connectionString = connectionString?.Substring(0, Math.Min(50, connectionString?.Length ?? 0)) + "...",
                    entityFrameworkConnection = canConnect
                },
                mongodb = new
                {
                    connectionString = mongoConnectionString?.Substring(0, Math.Min(50, mongoConnectionString?.Length ?? 0)) + "...",
                    configured = !string.IsNullOrEmpty(mongoConnectionString)
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error testing connections");
            return StatusCode(500, new { 
                message = "Connection test failed", 
                error = ex.Message,
                stackTrace = ex.StackTrace?.Substring(0, Math.Min(500, ex.StackTrace?.Length ?? 0))
            });
        }
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        try
        {
            var users = await _userManager.Users.Select(u => new
            {
                Id = u.Id.ToString(),
                UserName = u.UserName,
                Email = u.Email,
                IsPrivate = u.IsPrivate,
                CreatedAt = u.CreatedAt
            }).ToListAsync();

            return Ok(users);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting all users");
            return StatusCode(500, "Internal server error");
        }
    }
}

public class RegisterDto
{
    [Required]
    [StringLength(50, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(100)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(100, MinimumLength = 8)]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    public bool? IsPrivate { get; set; }
}

public class LoginDto
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; } = false;
}

public class UpdateUserDto
{
    [EmailAddress]
    [StringLength(100)]
    public string? Email { get; set; }

    public bool? IsPrivate { get; set; }
}

public class ChangePasswordDto
{
    [Required]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required]
    [StringLength(100, MinimumLength = 8)]
    public string NewPassword { get; set; } = string.Empty;
}

public class RefreshTokenDto
{
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}