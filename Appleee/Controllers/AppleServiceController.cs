using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ORAA.Data;
using ORAA.Models.Apple;
using ORAA.Services.Interfaces;

namespace ORAA.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AppleServiceController : ControllerBase
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private readonly IAppleService _appleService;
        private readonly DataContext _context;
        private readonly ILogger<AppleServiceController> _logger;

        public AppleServiceController(IAppleService applePayment, DataContext context, ILogger<AppleServiceController> logger)
        {
            _appleService = applePayment;
            _context = context;
            _logger = logger;
        }

        // Test endpoint to verify the API is working
        [HttpGet("test")]
        public IActionResult Test()
        {
            _logger.LogInformation("Test endpoint called");
            return Ok(new
            {
                message = "C# Apple Service API is working",
                timestamp = DateTime.UtcNow,
                version = "1.0",
                environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Unknown"
            });
        }

        // Alternative test endpoint
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new
            {
                message = "Apple Service Controller is running",
                availableEndpoints = new[] {
                    "GET /api/AppleService/test",
                    "GET /api/AppleService/apple/login",
                    "POST /api/AppleService/auth/apple-callback"
                }
            });
        }

        [HttpGet("apple/login")]
        public IActionResult StartAppleLogin()
        {
            try
            {
                var clientId = "com.mghebro.si";
                var redirectUri = "https://mghebro-auth-test.netlify.app/auth/apple/callback";
                var scope = "name email";

                var url = $"https://appleid.apple.com/auth/authorize?" +
                          $"client_id={clientId}&" +
                          $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                          $"response_type=code&" +
                          $"response_mode=form_post&" +
                          $"scope={scope}";

                return Redirect(url);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in StartAppleLogin");
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("auth/apple-callback")]
        public async Task<IActionResult> AppleCallback([FromBody] AppleAuthRequest request)
        {
            try
            {
                _logger.LogInformation("Apple callback received");
                _logger.LogInformation("Request data: {Request}", System.Text.Json.JsonSerializer.Serialize(request));

                // Validate the request
                if (request == null)
                {
                    _logger.LogWarning("Null request received");
                    return BadRequest(new { message = "Request body is null" });
                }

                // Validate required fields
                if (string.IsNullOrEmpty(request.AppleId))
                {
                    _logger.LogWarning("Apple ID is missing from request");
                    return BadRequest(new { message = "Apple ID is required" });
                }

                // Check if user already exists
                var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.AppleId == request.AppleId);
                if (existingUser != null)
                {
                    _logger.LogInformation("Existing user found: {UserId}", existingUser.Id);

                    // User exists, update last login and return success
                    existingUser.LastLoginAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    return Ok(new
                    {
                        status = 200,
                        message = "User already exists and logged in successfully.",
                        data = new
                        {
                            accessToken = "existing-user-token-" + Guid.NewGuid().ToString("N")[..16], // Generate actual JWT here
                            email = existingUser.Email,
                            appleId = existingUser.AppleId,
                            isNewUser = false
                        }
                    });
                }

                // Process new user registration
                _logger.LogInformation("Processing new user registration");
                var result = await _appleService.AppleLogin(request);

                _logger.LogInformation("Apple service result: {Result}", System.Text.Json.JsonSerializer.Serialize(result));

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in AppleCallback: {Message}", ex.Message);

                return StatusCode(500, new
                {
                    message = ex.Message,
                    timestamp = DateTime.UtcNow,
                    details = ex.InnerException?.Message,
                    type = ex.GetType().Name
                });
            }
        }

        // Handle preflight requests for CORS
        [HttpOptions("auth/apple-callback")]
        public IActionResult PreflightAppleCallback()
        {
            _logger.LogInformation("CORS preflight request received");
            return Ok();
        }

        // Catch-all for debugging routing issues
        [HttpPost("debug")]
        [HttpGet("debug")]
        public IActionResult Debug()
        {
            var requestInfo = new
            {
                Method = Request.Method,
                Path = Request.Path,
                Query = Request.Query.ToDictionary(q => q.Key, q => q.Value.ToString()),
                Headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                ContentType = Request.ContentType,
                ContentLength = Request.ContentLength
            };

            return Ok(new
            {
                message = "Debug endpoint hit",
                timestamp = DateTime.UtcNow,
                request = requestInfo
            });
        }
    }
}