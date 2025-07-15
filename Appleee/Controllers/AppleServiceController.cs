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
        public AppleServiceController(IAppleService applePayment , DataContext context)
        {
            _appleService = applePayment;
            _context = context;
        }

        [HttpGet("AppleService/apple1")]
        public IActionResult StartAppleLogin()
        {
            var clientId = "com.mghebro.si";
            var redirectUri = "https://mghebro-auth-test.netlify.app/auth/apple/callback"; //front
            var scope = "name email";

            var url = $"https://appleid.apple.com/auth/authorize?" +
                      $"client_id={clientId}&" +
                      $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                      $"response_type=code&" +
                      $"response_mode=form_post&" +
                      $"scope={scope}";

            if (_context.Users.Any(u => u.AppleId != null ))
            {
                return Conflict("User already exists.");
            }


            return Redirect(url);
        }

        [HttpPost("auth/apple-callback")]
        public async Task<IActionResult> AppleLogin([FromBody] AppleAuthRequest request)
        {
            var dataToReturn = _appleService.AppleLogin(request);

            return Ok(dataToReturn);
        }
       
    }
}
