using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Identity.Entities;

public class User : IdentityUser<Guid>
{
    public bool IsPrivate { get; set; } = false;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
} 