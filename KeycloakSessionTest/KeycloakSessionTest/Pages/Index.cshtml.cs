using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace KeycloakSessionTest.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public JwtSecurityToken? Token { get; private set; }
        public AuthenticationTicket? Ticket { get; private set; }

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public async Task OnGetAsync()
        {
            string? token = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            JwtSecurityTokenHandler handler = new();
            Token = handler.ReadJwtToken(token);

            AuthenticateResult auth = await HttpContext.AuthenticateAsync();
            Ticket = auth.Ticket;
        }
    }
}