namespace Identity.Entities;

// A durable PostgreSQL outbox; success removes the work only after Mongo/User acknowledges it.
public class ProfileSyncWork : BaseEntity
{
    public Guid UserId { get; set; }
    public bool Delete { get; set; }
    public int Attempts { get; set; }
    public DateTime NextAttemptAt { get; set; } = DateTime.UtcNow;
}
