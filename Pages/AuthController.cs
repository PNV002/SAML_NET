// This package allows for SAML 2.0 authentication and integration in ASP.NET Core applications.
using ITfoxtec.Identity.Saml2;
// Contains classes representing the SAML 2.0 XML schemas.
using ITfoxtec.Identity.Saml2.Schemas;
// Provides extensions and helpers for integrating SAML 2.0 authentication with ASP.NET Core MVC applications.
using ITfoxtec.Identity.Saml2.MvcCore;
// Provides attributes and classes for implementing authorization in ASP.NET Core MVC applications.
using Microsoft.AspNetCore.Authorization;
// Contains classes for building and managing ASP.NET Core MVC controllers.
using Microsoft.AspNetCore.Mvc;
// Provides options for configuring various aspects of the application.
using Microsoft.Extensions.Options;
// Contains classes for handling exceptions related to authentication and authorization.
using System.Security.Authentication;
// Provides classes and methods for handling authentication-related tasks in ASP.NET Core applications.
using Microsoft.AspNetCore.Authentication;

// Controller to handle SAML authentication routing
namespace Okta_SAML_Example.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;
        private readonly IConfiguration configuration;
       
        // Constructor injection to get the SAML configuration.
        public AuthController(IOptions<Saml2Configuration> configAccessor, IConfiguration configuration)
        {
            // Retrieve the configured Saml2Configuration instance
            config = configAccessor.Value;
            // Store the IConfiguration instance
            this.configuration = configuration;
        }

        [Route("Login")] // Specifies the route for the login action.
        public IActionResult Login(string returnUrl = null)
        {
            var authnRequest = new Saml2AuthnRequest(config);
            var binding = new Saml2RedirectBinding();
            // Set the relay state query with the return URL.
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl?? Url.Content("~/") } });

            // Return the SAML request to the browser
            return binding.Bind(authnRequest).ToActionResult();

        }
          
        // The AssertionConsumerService action handles the SAML response from Okta.  
        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {       
            var binding = new Saml2PostBinding();

            // Create a new instance of Saml2AuthnResponse to hold the SAML response.            
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            // Read the SAML response from the HTTP request and populate the saml2AuthnResponse object.
            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);

            Console.WriteLine("SAML Response:" + saml2AuthnResponse.XmlDocument?.OuterXml);

            // Throw an exception if the SAML response status is not successful.
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            
            Console.WriteLine();
            Console.WriteLine("User Attributes:");

            // Parse claims from SAML response
            foreach (var claim in saml2AuthnResponse.ClaimsIdentity.Claims)
            {
                Console.WriteLine($"{claim.Type}: {claim.Value}");
                Console.WriteLine();
            }
            // // Create a session for the authenticated user.
            await saml2AuthnResponse.CreateSession(HttpContext);

            // Redirect the user to the dashboard page.
            return Redirect("/Dashboard");
        }

        // Action method to handle the logout process.
        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            // Redirect the user to the home page if not authenticated.
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }
            
             // Clear the user session.
            await HttpContext.SignOutAsync();

            // Redirect to the home page after logout
            var oktaLogoutUrl = configuration["Saml2:LogoutUrl"]; 
            return Redirect(oktaLogoutUrl);
        }
    }
}
