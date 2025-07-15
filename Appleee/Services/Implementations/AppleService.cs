using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Azure.Core;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Google;
using Jose;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using ORAA.Core;
using ORAA.Data;
using ORAA.DTO;
using ORAA.Enums;
using ORAA.Models;
using ORAA.Models.Apple;
using ORAA.Services.Interfaces;
using Stripe;

namespace ORAA.Services.Implementations
{   
    public class AppleService : IAppleService
    {
        private readonly HttpClient _httpClient;
        private readonly UserManager<User> _userManager;
        private readonly DataContext _context;
        private readonly IJWTService _jWTService; // Assuming you have a JWT token service

        public AppleService(
            HttpClient httpClient,
            UserManager<User> userManager,
            DataContext context,
            IJWTService jWTService)
        {
            _httpClient = httpClient;
            _userManager = userManager;
            _context = context;
            _jWTService = jWTService;
        }
        public async Task<ApiResponse<AppleTokenResponseDTO>> AppleLogin(AppleAuthRequest request)
        {
            try
            {
                var AppleclientId = "com.mghebro.si";
                var teamId = "TTFPHSNRGQ";
                var keyId = "ZR62KJ2BYT";
                var privateKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "Core", "Certificate", "AuthKey_ZR62KJ2BYT.p8");

                var clientSecret = GenerateClientSecret(teamId, AppleclientId, keyId, privateKeyPath);

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
                        return new ApiResponse<AppleTokenResponseDTO>
                        {
                            Status = StatusCodes.Status400BadRequest,
                            Message = "Failed to create user account: " + string.Join(", ", createResult.Errors.Select(e => e.Description)),
                            Data = null
                        };
                    }
                }
                else
                {
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

                return new ApiResponse<AppleTokenResponseDTO>
                {
                    Data = appleTokenResponseDTO,
                    Status = StatusCodes.Status200OK,
                    Message = "Login successful"
                };
            }
            catch (Exception ex)
            {
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
                { "exp", now.AddMinutes(10).ToUnixTimeSeconds() }, // Apple allows up to 6 months, but use short time for security
                { "aud", "https://appleid.apple.com" },
                { "sub", clientId }
            };

            var headers = new Dictionary<string, object>
            {
                { "kid", keyId }
            };

            return JWT.Encode(payload, ecdsa, JwsAlgorithm.ES256, headers);
        }

        public async Task<string> ValidateApplePaySessionAsync(string validationUrl)
        {
            var certPath = "Certificates/apple-pay-cert.p12"; 
            var certPassword = "your_password"; 

            var certificate = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.MachineKeySet);
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(certificate);

            var client = new HttpClient(handler);

            var payload = new
            {
                merchantIdentifier = "merchant.com.yourdomain",
                displayName = "Your Store",
                initiative = "web",
                initiativeContext = "yourdomain.com"
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await client.PostAsync(validationUrl, content);
            return await response.Content.ReadAsStringAsync();
        }
    }
    
}
