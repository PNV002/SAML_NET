//SAML
using ITfoxtec.Identity.Saml2; //contains classes for SAML authentication
using ITfoxtec.Identity.Saml2.Schemas.Metadata; //contains metadata schemas for SAML
using ITfoxtec.Identity.Saml2.MvcCore.Configuration; //contains configuration options for SAML in ASP.NET Core MVC
//END SAML

namespace Okta_SAML_Example
{
    // Startup class responsible for configuring the application
    public class Startup
    {
        // Constructor to initialize the Startup class with IConfiguration
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        
        // IConfiguration instance to access configuration settings
        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container. Code added for SAML Authentication.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add Razor Pages support
            services.AddRazorPages();

            // Register SAML settings from appsettings.json
            services.Configure<Saml2Configuration>(Configuration.GetSection("Saml2"));
            
            // Configure SAML settings dynamically
            services.Configure<Saml2Configuration>(saml2Configuration =>
            {
                // Add allowed audience URIs              
                saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);
                
                // Read IdP SSO descriptor from metadata URL
                var entityDescriptor = new EntityDescriptor();
                entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Configuration["Saml2:IdPMetadata"]));
                
                // Configure SAML settings based on IdP SSO descriptor
                if (entityDescriptor.IdPSsoDescriptor != null)
                {
                    saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                    saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                }
                else
                {
                    throw new Exception("IdPSsoDescriptor not loaded from metadata.");
                }
            });

            // Add SAML authentication services
            services.AddSaml2();  
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline. 
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            // Enable HTTPS redirection and static file serving
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            // Enable routing and SAML authentication
            app.UseRouting();
            app.UseSaml2(); //SAML
            app.UseAuthorization();

            // Configure endpoints. 
            //Code added for SAML Authentication to configure default controller route for handling authentication requests.
            app.UseEndpoints(endpoints =>
            {
                // Maps Razor pages to endpoints
                endpoints.MapRazorPages(); 

                // Configure default controller route        
                //SAML
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                //END SAML
            });
        }
    }
}
