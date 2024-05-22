using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace Okta_SAML_Example.Pages
{
    public class DashboardModel : PageModel
    {
        public string UserName { get; set; }

        public void OnGet()
        {
            var identity = (ClaimsIdentity)User.Identity;
            UserName = identity.FindFirst(ClaimTypes.Name)?.Value;
        }
    }
}