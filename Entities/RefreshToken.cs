using System.ComponentModel.DataAnnotations;

namespace Identity.Entities;

public class RefreshToken : BaseEntity
{
    [Required]
    public Guid UserId { get; set; }

    [Required]
    [MaxLength(500)]
    public string Token { get; set; } = string.Empty;

    [Required]
    public DateTime ExpiresAt { get; set; }

    public bool IsRevoked { get; set; } = false;

    // Navigation properties
    public virtual User User { get; set; } = null!;
} 