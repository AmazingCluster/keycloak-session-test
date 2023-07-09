using KeycloakSessionTest.Tokens;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace KeycloakSessionTest
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorPages();

            builder.Services
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    //options.ExpireTimeSpan = TimeSpan.FromMinutes(25);

                    options.SlidingExpiration = true;
                    options.Events.OnCheckSlidingExpiration = async context =>
                    {
                        AuthenticationStateRefreshProvider provider = context.HttpContext.RequestServices.GetRequiredService<AuthenticationStateRefreshProvider>();
                        context.ShouldRenew = await provider.RefreshTokensAsync(context.ShouldRenew, context.Properties, context.HttpContext.RequestAborted);
                    };
                })
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.MetadataAddress = "https://keycloak.jaspervannoordenburg.nl/realms/StaterSSO/.well-known/openid-configuration";

                    options.ClientId = "test.sessions";
                    options.ClientSecret = "d1zjrJ6qzcCvJckThzCnuaB0bPaUo6ga";
                    options.ResponseType = "code";

                    options.GetClaimsFromUserInfoEndpoint = true;

                    options.UseTokenLifetime = true;
                    options.SaveTokens = true;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true
                    };
                });

            builder.Services.AddAuthorization(options =>
            {
                // By default, all incoming requests will be authorized according to the default policy
                options.FallbackPolicy = options.DefaultPolicy;
            });

            builder.Services.AddSession();

            builder.Services
                .AddTransient<IOpenIdConnectConfigurationProvider, OidcEndpointConfigurationProvider>();

            builder.Services
                .AddTransient<IOidcClient, OidcClient>()                
                .AddHttpClient<OidcClient>();

            builder.Services.AddTransient<AuthenticationStateRefreshProvider>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }            

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseSession();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapRazorPages();

            app.Run();
        }
    }
}