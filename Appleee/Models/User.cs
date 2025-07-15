using Microsoft.AspNetCore.Identity;
using ORAA.Enums;

namespace ORAA.Models
{
    public class User : IdentityUser<int>
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public ACCOUNT_STATUS Status { get; set; } = ACCOUNT_STATUS.CODE_SENT;
        public ROLES Role { get; set; } = ROLES.USER;
        public bool IsVerified { get; set; }
        public string? VerificationCode { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; }
        public bool EmailNotifications { get; set; }
        public bool SmsNotifications { get; set; }
        public bool PushNotifications { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiresAtUtc { get; set; }
        public string? PasswordResetCode { get; set; }
        public string? GoogleId { get; set; }
        public string? AppleId { get; set; }

        // Navigation properties for related entities

    }
}
