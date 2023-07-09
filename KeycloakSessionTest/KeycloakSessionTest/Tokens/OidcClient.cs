using System.Text.Json;
using KeycloakSessionTest.Tokens.Models;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace KeycloakSessionTest.Tokens
{
    public interface IOidcClient
    {
        Task<TokenResponse> RefreshTokenAsync(string scheme, string refreshToken, CancellationToken cancellationToken);
    }

    public class OidcClient : IOidcClient
    {
        private HttpClient HttpClient { get; }
        private IOpenIdConnectConfigurationProvider ConfigurationProvider { get; }
        private IOptionsSnapshot<OpenIdConnectOptions> Options { get; }

        public OidcClient(HttpClient httpClient, IOpenIdConnectConfigurationProvider configurationProvider, IOptionsSnapshot<OpenIdConnectOptions> options)
        {
            HttpClient = httpClient;
            ConfigurationProvider = configurationProvider;
            Options = options;
        }

        public async Task<TokenResponse> RefreshTokenAsync(string scheme, string refreshToken, CancellationToken cancellationToken)
        {
            OpenIdConnectConfiguration configuration = await ConfigurationProvider.GetConfigurationAsync(scheme, cancellationToken);

            OpenIdConnectOptions options = Options.Get(scheme);

            Dictionary<string, string> values = new Dictionary<string, string>
            {
                { OpenIdConnectParameterNames.GrantType, OpenIdConnectParameterNames.RefreshToken },
                { OpenIdConnectParameterNames.RefreshToken, refreshToken },
                { OpenIdConnectParameterNames.Scope, string.Join(' ', options.Scope) },
            };

            if (string.IsNullOrEmpty(options.ClientId) is false)
            {
                values.Add(OpenIdConnectParameterNames.ClientId, options.ClientId!);
            }

            if (string.IsNullOrEmpty(options.ClientSecret) is false)
            {
                values.Add(OpenIdConnectParameterNames.ClientSecret, options.ClientSecret!);
            }

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(values)
            };

            HttpResponseMessage response = await HttpClient.SendAsync(request, cancellationToken);

            response.EnsureSuccessStatusCode();

            Stream responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);

            return (await JsonSerializer.DeserializeAsync<TokenResponse>(responseStream, cancellationToken: cancellationToken))!;
        }

    }
}
