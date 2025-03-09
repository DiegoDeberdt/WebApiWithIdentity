using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace WebApiWithIdentity.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // Requires authentication
    public class ProtectedController : ControllerBase
    {
        [HttpGet("data")]
        public IActionResult GetData()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value; // Retrieve the email claim

            if (string.IsNullOrEmpty(email))
            {
                return NotFound("Email claim not found");
            }

            return Ok(new { Message = "This is protected data for user: " + email });
        }

        [HttpGet("download")]
        public IActionResult DownloadFile()
        {
            var fileBytes = System.IO.File.ReadAllBytes("C:\\Temp\\CV.pdf");
            return File(fileBytes, "application/pdf", "CV.pdf");
        }

    }
}
