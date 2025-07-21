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
        try
        {
            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
            {
                return BadRequest(new { message = "User with this email already exists" });
            }

            existingUser = await _userManager.FindByNameAsync(dto.Username);
            if (existingUser != null)
            {
                return BadRequest(new { message = "Username is already taken" });
            }

            var user = new User
            {
                UserName = dto.Username,
                Email = dto.Email,
                IsPrivate = dto.IsPrivate ?? false,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "User");
                try
                {
                    await _userSyncService.SyncUserToMongoDbAsync(user);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to sync user {UserId} to MongoDB during registration", user.Id);
                }

                _logger.LogInformation("User {UserId} registered successfully", user.Id);
                return Ok(new { message = "User registered successfully", userId = user.Id });
            }

            return BadRequest(new { message = "Registration failed", errors = result.Errors.Select(e => e.Description) });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            return StatusCode(500, new { message = "An error occurred during registration" });
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