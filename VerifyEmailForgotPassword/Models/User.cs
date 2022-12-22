namespace VerifyEmailForgotPassword.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public byte[] PasswordHsh { get; set; } = new byte[32];
        public byte[] PasswordSalt { get; set; } = new byte[32];
        public string? VericationToken { get; set; }
        public DateTime? VerifiedAl { get; set; }
        public string? PasswordResetToken { get; set; }
        public DateTime? ResetTokenExpires { get; set; }
    }

    }
