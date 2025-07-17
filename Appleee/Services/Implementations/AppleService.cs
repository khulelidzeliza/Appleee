using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Jose;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ORAA.Core;
using ORAA.Data;
using ORAA.DTO;
using ORAA.Enums;
using ORAA.Models;
using ORAA.Models.Apple;
using ORAA.Services.Interfaces;

namespace ORAA.Services.Implementations
{
    public class AppleService : IAppleService
    {
        private readonly HttpClient _httpClient;
        private readonly UserManager<User> _userManager;
        private readonly DataContext _context;
        private readonly IJWTService _jWTService;
        private readonly ILogger<AppleService> _logger;

        public AppleService(
            HttpClient httpClient,
            UserManager<User> userManager,
            DataContext context,
            IJWTService jWTService,
            ILogger<AppleService> logger)
        {
            _httpClient = httpClient;
            _userManager = userManager;
            _context = context;
            _jWTService = jWTService;
            _logger = logger;
        }

        public async Task<ApiResponse<AppleTokenResponseDTO>> AppleLogin(AppleAuthRequest request)
        {
            try
            {
                _logger.LogInformation("Processing Apple login for AppleId: {AppleId}", request.AppleId);

                // Apple authentication configuration
                var AppleclientId = "com.mghebro.si";
                var teamId = "TTFPHSNRGQ";
                var keyId = "ZR62KJ2BYT";
                var privateKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "Core", "Certificate", "AuthKey_ZR62KJ2BYT.p8");

                // Generate client secret
                var clientSecret = GenerateClientSecret(teamId, AppleclientId, keyId, privateKeyPath);

                // Exchange authorization code for tokens
                var parameters = new Dictionary<string, string>
                {
                    {"client_id", AppleclientId },
                    {"client_secret", clientSecret },
                    {"code", request.Code },
                    {"grant_type", "authorization_code" },
                    {"redirect_uri", request.RedirectUri }
                };

                var content = new FormUrlEncodedContent(parameters);
                var response = await _httpClient.PostAsync("https://appleid.apple.com/auth/token", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Apple token exchange failed: {Error}", errorContent);
                    return new ApiResponse<AppleTokenResponseDTO>
                    {
                        Status = (int)response.StatusCode,
                        Message = $"Apple authentication failed: {errorContent}",
                        Data = null
                    };
                }

                var responseString = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<AppleTokenResponse>(responseString,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                // Decode the ID token
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(tokenResponse.id_token);
                var payload = JsonSerializer.Deserialize<AppleIdTokenPayload>(
                    JsonSerializer.Serialize(jwtToken.Payload),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                // Find or create user
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.AppleId == payload.sub ||
                                             (u.Email == payload.email && u.EmailConfirmed));

                if (user == null)
                {
                    _logger.LogInformation("Creating new user for Apple ID: {AppleId}", payload.sub);

                    // Create new user
                    user = new User
                    {
                        UserName = payload.email ?? $"apple_{payload.sub}",
                        Email = payload.email,
                        AppleId = payload.sub,
                        EmailConfirmed = payload.email_verified,
                        IsVerified = true,
                        FirstName = request.Name?.Split(' ').FirstOrDefault() ?? "",
                        LastName = request.Name?.Split(' ').Skip(1).FirstOrDefault() ?? "",
                        Status = ACCOUNT_STATUS.VERIFIED,
                        Role = ROLES.USER,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        IsActive = true
                    };

                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        _logger.LogError("Failed to create user: {Errors}",
                            string.Join(", ", createResult.Errors.Select(e => e.Description)));

                        return new ApiResponse<AppleTokenResponseDTO>
                        {
                            Status = StatusCodes.Status400BadRequest,
                            Message = "Failed to create user account: " + string.Join(", ", createResult.Errors.Select(e => e.Description)),
                            Data = null
                        };
                    }

                    _logger.LogInformation("Successfully created new user with ID: {UserId}", user.Id);
                }
                else
                {
                    _logger.LogInformation("Found existing user: {UserId}", user.Id);

                    // Update existing user
                    if (string.IsNullOrEmpty(user.AppleId))
                    {
                        user.AppleId = payload.sub;
                    }

                    user.LastLoginAt = DateTime.UtcNow;
                    user.UpdatedAt = DateTime.UtcNow;

                    await _userManager.UpdateAsync(user);
                }

                // Generate your app's JWT token
                var userToken = _jWTService.GetUserToken(user);
                var refreshToken = _jWTService.GenerateRefreshToken();

                // Save refresh token
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiresAtUtc = DateTime.UtcNow.AddDays(30);
                await _userManager.UpdateAsync(user);

                // Create the response DTO
                var appleTokenResponseDTO = new AppleTokenResponseDTO
                {
                    Email = user.Email,
                    AppleId = user.AppleId,
                    AccessToken = userToken.Token,
                    RefreshToken = refreshToken
                };

                _logger.LogInformation("Successfully processed Apple login for user: {UserId}", user.Id);

                return new ApiResponse<AppleTokenResponseDTO>
                {
                    Data = appleTokenResponseDTO,
                    Status = StatusCodes.Status200OK,
                    Message = "Login successful"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in AppleLogin: {Message}", ex.Message);

                return new ApiResponse<AppleTokenResponseDTO>
                {
                    Status = StatusCodes.Status500InternalServerError,
                    Message = $"Internal server error: {ex.Message}",
                    Data = null
                };
            }
        }

        public static string GenerateClientSecret(string teamId, string clientId, string keyId, string privateKeyPath)
        {
            var privateKeyText = System.IO.File.ReadAllText(privateKeyPath)
                                  .Replace("-----BEGIN PRIVATE KEY-----", string.Empty)
                                  .Replace("-----END PRIVATE KEY-----", string.Empty)
                                  .Replace("\n", string.Empty)
                                  .Replace("\r", string.Empty);

            var keyBytes = Convert.FromBase64String(privateKeyText);
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(keyBytes, out _);

            var now = DateTimeOffset.UtcNow;

            var payload = new Dictionary<string, object>
            {
                { "iss", teamId },
                { "iat", now.ToUnixTimeSeconds() },
                { "exp", now.AddMinutes(10).ToUnixTimeSeconds() },
                { "aud", "https://appleid.apple.com" },
                { "sub", clientId }
            };

            var headers = new Dictionary<string, object>
            {
                { "kid", keyId }
            };

            return JWT.Encode(payload, ecdsa, JwsAlgorithm.ES256, headers);
        }

        // Keep this method for Apple Pay validation if needed
        public async Task<string> ValidateApplePaySessionAsync(string validationUrl)
        {
            // Implementation for Apple Pay (different from Sign in with Apple)
            throw new NotImplementedException("Apple Pay validation not implemented in this example");
        }
    }
}