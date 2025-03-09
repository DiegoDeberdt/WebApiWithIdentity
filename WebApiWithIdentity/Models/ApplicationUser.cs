using Microsoft.AspNetCore.Identity;

namespace WebApiWithIdentity.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }
        public string? FavoriteColor { get; set; }
    }
}
