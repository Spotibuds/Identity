using System.Net.Mail;
using System.Net.Sockets;

namespace Identity.Services;

public interface IRecoveryMailer
{
    Task CheckAvailableAsync(CancellationToken ct);
    Task SendAsync(string email, string token, CancellationToken ct);
}

public class RecoveryMailer(IConfiguration config) : IRecoveryMailer
{
    public async Task CheckAvailableAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(config.Required("Smtp:Host"), config.GetValue("Smtp:Port", 1025), timeout.Token);
    }

    public async Task SendAsync(string email, string token, CancellationToken ct)
    {
        var link = config.Required("Frontend:PublicUrl").TrimEnd('/') + "/reset-password?email=" + Uri.EscapeDataString(email) + "&token=" + Uri.EscapeDataString(token);
        using var message = new MailMessage(config.Required("Smtp:From"), email, "Reset your Spotibuds password",
            $"Use this single-use link within 20 minutes to reset your password:\n\n{link}\n\nIf you did not request this, ignore this message.");
        using var smtp = new SmtpClient(config.Required("Smtp:Host"), config.GetValue("Smtp:Port", 1025))
            { EnableSsl = false, Timeout = 5000 };
        await smtp.SendMailAsync(message, ct);
    }
}
