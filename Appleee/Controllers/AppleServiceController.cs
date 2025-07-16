using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ORAA.Data;
using ORAA.Models.Apple;
using ORAA.Services.Interfaces;

namespace ORAA.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AppleServiceController : ControllerBase
    {
        private readonly IAppleService _appleService;
        private readonly DataContext _context;
        private readonly ILogger<AppleServiceController> _logger;

        public AppleServiceController(IAppleService appleService, DataContext context, ILogger<AppleServiceController> logger)
        {
            _appleService = appleService;
            _context = context;
            _logger = logger;
        }

        [HttpGet("apple/login")]
        public IActionResult StartAppleLogin()
        {
            var clientId = "com.mghebro.si";
            var redirectUri = "https://mghebro-auth-test-angular.netlify.app/.netlify/functions/server";
            var scope = "name email";

            var url = $"https://appleid.apple.com/auth/authorize?" +
                      $"client_id={clientId}&" +
                      $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                      $"response_type=code&" +
                      $"response_mode=form_post&" +
                      $"scope={scope}";

            return Redirect(url);
        }

        [HttpPost("auth/apple-callback")]
        public async Task<IActionResult> AppleCallback([FromBody] AppleAuthRequest request)
        {
            try
            {
                _logger.LogInformation("Apple callback received for AppleId: {AppleId}", request.AppleId);

                // Validate required fields
                if (string.IsNullOrEmpty(request.AppleId))
                {
                    _logger.LogWarning("Apple callback missing AppleId");
                    return BadRequest(new { message = "AppleId is required" });
                }

                // Check if user already exists by AppleId first, then by email
                var existingUser = await _context.Users
                    .FirstOrDefaultAsync(u => u.AppleId == request.AppleId ||
                                            (u.Email == request.Email && !string.IsNullOrEmpty(request.Email)));

                if (existingUser != null)
                {
                    _logger.LogWarning("User already exists with AppleId: {AppleId} or Email: {Email}",
                        request.AppleId, request.Email);

                    // Update the redirect URI for consistency
                    request.RedirectUri = "https://mghebro-auth-test-angular.netlify.app/.netlify/functions/server";

                    // Still process the login even if user exists
                    var loginResult = await _appleService.AppleLogin(request);

                    if (loginResult.Status == 200)
                    {
                        return Ok(loginResult.Data);
                    }
                    else
                    {
                        return StatusCode(loginResult.Status, new { message = loginResult.Message });
                    }
                }

                // Set the correct redirect URI
                request.RedirectUri = "https://mghebro-auth-test-angular.netlify.app/.netlify/functions/server";

                var result = await _appleService.AppleLogin(request);

                if (result.Status == 200)
                {
                    _logger.LogInformation("Apple login successful for AppleId: {AppleId}", request.AppleId);
                    return Ok(result.Data);
                }
                else
                {
                    _logger.LogError("Apple login failed for AppleId: {AppleId}. Status: {Status}, Message: {Message}",
                        request.AppleId, result.Status, result.Message);
                    return StatusCode(result.Status, new { message = result.Message });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing Apple callback for AppleId: {AppleId}", request.AppleId);
                return StatusCode(500, new
                {
                    message = "Internal server error during Apple authentication",
                    error = ex.Message
                });
            }
        }

        [HttpOptions("auth/apple-callback")]
        public IActionResult PreflightAppleCallback()
        {
            return Ok();
        }
    }
}