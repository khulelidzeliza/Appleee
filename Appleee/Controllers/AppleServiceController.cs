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
        private readonly HttpClient _httpClient = new HttpClient();
        private readonly IAppleService _appleService;
        private readonly DataContext _context;

        public AppleServiceController(IAppleService applePayment, DataContext context)
        {
            _appleService = applePayment;
            _context = context;
        }

        [HttpGet("apple/login")]
        public IActionResult StartAppleLogin()
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

        [HttpPost("auth/apple-callback")]
        public async Task<IActionResult> AppleCallback([FromBody] AppleAuthRequest request)
        {
            try
            {
                // Check if user already exists
                if (await _context.Users.AnyAsync(u => u.AppleId == request.AppleId))
                {
                    return Conflict(new { message = "User already exists." });
                }

                var result = await _appleService.AppleLogin(request);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}