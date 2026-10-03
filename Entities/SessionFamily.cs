namespace Identity.Entities;

// The durable session row is also the per-family PostgreSQL lock. Logout remains effective
// even when a refresh was already waiting or a successor is inserted concurrently.
public class SessionFamily : BaseEntity
{
    public Guid UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public User User { get; set; } = null!;
}
