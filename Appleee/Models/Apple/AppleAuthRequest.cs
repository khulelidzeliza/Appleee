namespace ORAA.Models.Apple;

public class AppleAuthRequest
{
    public string Code { get; set; }           // authorization code from frontend
    public string RedirectUri { get; set; }    // must match the one used in frontend
    public string? AppleId { get; set; }       // Apple's unique user identifier
    public string? Email { get; set; }         // User's email (if provided)
    public string? Name { get; set; }          // User's name (only on first sign-in)
    public bool IsPrivateEmail { get; set; }   // Whether email is a private relay
    public string? RefreshToken { get; set; }  // Refresh token from Apple
    public string? AccessToken { get; set; }   // Access token from Apple
}