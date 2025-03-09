using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApiWithIdentity.Models;

namespace WebApiWithIdentity.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthController(
            IConfiguration configuration,
            ILogger<AuthController> logger,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _configuration = configuration;
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FullName = model.FullName
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            return result.Succeeded
                ? Ok(new { Message = "User registered successfully" })
                : BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Unauthorized(new { Message = "Invalid username or password" });
            }

            var token = GenerateJwtToken(user);
            return Ok(new { Token = token });
        }

        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            return InitiateExternalLogin("Google", nameof(GoogleLoginCallback));
        }

        [HttpGet("microsoft-login")]
        public IActionResult MicrosoftLogin()
        {
            return InitiateExternalLogin("Microsoft", nameof(MicrosoftLoginCallback));
        }

        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleLoginCallback()
        {
            var result = await HttpContext.AuthenticateAsync("Google");
            return await HandleExternalLoginCallback(result);
        }

        [HttpGet("microsoft-callback")]
        public async Task<IActionResult> MicrosoftLoginCallback()
        {
            var result = await HttpContext.AuthenticateAsync("Microsoft");
            return await HandleExternalLoginCallback(result);
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User signed out");
            return Ok(new { Token = CreateInvalidJwtToken() });
        }

        #region Private Helper Methods

        private IActionResult InitiateExternalLogin(string provider, string callbackAction)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action(callbackAction, "Auth")
            };
            return Challenge(properties, provider);
        }

        private async Task<IActionResult> HandleExternalLoginCallback(AuthenticateResult result)
        {
            if (!result.Succeeded || result.Principal == null)
            {
                _logger.LogError("External authentication failed");
                return BadRequest("External authentication error");
            }

            try
            {
                var email = result.Principal.FindFirstValue(ClaimTypes.Email);
                var name = result.Principal.FindFirstValue(ClaimTypes.Name);
                var picture = result.Principal.FindFirstValue("urn:google:picture")
                           ?? result.Principal.FindFirstValue("urn:microsoft:picture");
                var providerKey = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
                var loginProvider = result.Properties.Items[".AuthScheme"];

                _logger.LogInformation($"External authentication {loginProvider} for {email}");

                var user = await EnsureUserExists(email, name, loginProvider, providerKey);
                await _signInManager.SignInAsync(user, isPersistent: false);

                var jwtToken = GenerateJwtToken(user);
                _logger.LogInformation("Generated JWT token");

                return Redirect($"{_configuration["ClientUrl"]}/login?token={jwtToken}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing external login");
                return BadRequest("Error processing external authentication");
            }
        }

        private async Task<ApplicationUser> EnsureUserExists(string email, string name, string loginProvider, string providerKey)
        {
            var user = await _userManager.FindByLoginAsync(loginProvider, providerKey);
            if (user != null)
            {
                _logger.LogInformation("Logged existing user");
                return user;
            }

            user = new ApplicationUser { UserName = email, Email = email, FullName = name };
            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                _logger.LogError("Error creating user: {@Errors}", createResult.Errors);
                throw new Exception("Failed to create user");
            }

            var addLoginResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(loginProvider, providerKey, loginProvider));
            if (!addLoginResult.Succeeded)
            {
                _logger.LogError("Error adding login: {@Errors}", addLoginResult.Errors);
                throw new Exception("Failed to add external login");
            }

            _logger.LogInformation("Created new user account");
            return user;
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id),
                new(ClaimTypes.Email, user.Email!),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var roles = _userManager.GetRolesAsync(user).Result;
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string CreateInvalidJwtToken()
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: new[] { new Claim("invalid", "true") },
                expires: DateTime.UtcNow.AddSeconds(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        #endregion
    }
}