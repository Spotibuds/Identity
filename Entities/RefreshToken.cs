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
    public Guid FamilyId { get; set; }
    public Guid? ReplacedById { get; set; }
    public bool IsPending { get; set; }
    public Guid? PreparedFromId { get; set; }
    [MaxLength(64)]
    public string? OperationHash { get; set; }
    public DateTime? PreparationExpiresAt { get; set; }

    // Navigation properties
    public virtual User User { get; set; } = null!;
}
