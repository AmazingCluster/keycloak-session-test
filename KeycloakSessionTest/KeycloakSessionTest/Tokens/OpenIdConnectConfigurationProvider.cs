using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace KeycloakSessionTest.Tokens
{
    public interface IOpenIdConnectConfigurationProvider
    {
        Task<OpenIdConnectConfiguration> GetConfigurationAsync(string scheme, CancellationToken cancellationToken);
    }

    public class OidcEndpointConfigurationProvider : IOpenIdConnectConfigurationProvider
    {
        private IOptionsSnapshot<OpenIdConnectOptions> Options { get; }

        public OidcEndpointConfigurationProvider(IOptionsSnapshot<OpenIdConnectOptions> options)
        {
            Options = options;
        }

        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string scheme, CancellationToken cancellationToken)
        {
            OpenIdConnectOptions openIdConnectOptions = Options.Get(scheme);

            if (openIdConnectOptions.Configuration is not null)
            {
                return openIdConnectOptions.Configuration;
            }

            if (openIdConnectOptions.ConfigurationManager is null)
            {
                throw new ArgumentException($"The configuration was null for scheme '{scheme}' and no {nameof(openIdConnectOptions.ConfigurationManager)} was configured. This should never happen as either one or the other should be available");
            }

            return await openIdConnectOptions.ConfigurationManager.GetConfigurationAsync(cancellationToken);
        }
    }
}