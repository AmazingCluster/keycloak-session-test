using System.IdentityModel.Tokens.Jwt;

using KeycloakSessionTest.Tokens.Exceptions;
using KeycloakSessionTest.Tokens.Models;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace KeycloakSessionTest.Tokens
{
    public class AuthenticationStateRefreshProvider
    {
        // TODO: Make configurable
        private static readonly TimeSpan ExpirationThresholdDelta = TimeSpan.FromSeconds(10);

        private IOidcClient OidcClient { get; }
        private IOptionsSnapshot<OpenIdConnectOptions> Options { get; }
        private ILogger<AuthenticationStateRefreshProvider> Logger { get; }

        public AuthenticationStateRefreshProvider(IOidcClient oidcClient, IOptionsSnapshot<OpenIdConnectOptions> options, ILogger<AuthenticationStateRefreshProvider> logger)
        {
            OidcClient = oidcClient;
            Options = options;
            Logger = logger;
        }

        public async Task<bool> RefreshTokensAsync(bool shouldRenew, AuthenticationProperties properties, CancellationToken cancellationToken)
        {
            string? scheme = properties.GetString(".AuthScheme");

            if (string.IsNullOrEmpty(scheme))
            {
                throw new InvalidOperationException($"Cannot determine authorization scheme as the property was not included in the {properties.GetType().FullName} values.");
            }

            OpenIdConnectOptions oidcOptions = Options.Get(scheme);

            if (ShouldRefreshToken(shouldRenew, oidcOptions.UseTokenLifetime, properties))
            {
                return await RefreshTokensAsync(scheme, oidcOptions.UseTokenLifetime, properties, cancellationToken) || shouldRenew;
            }

            return false;
        }

        private static bool ShouldRefreshToken(bool shouldRenew, bool useTokenLifetimeForTicket, AuthenticationProperties properties)
        {
            if (properties.AllowRefresh is false)
            {
                return false;
            }

            if (useTokenLifetimeForTicket)
            {
                return shouldRenew; // If using the tokenLifetime, the authentication ticket's validity is equal to the token's, thus an authentication state update should result in a token refresh.
            }

            // If not using the TokenLifetime, we always have to validate the token expiration ourselves
            string? accessToken = properties.GetTokenValue(OpenIdConnectParameterNames.AccessToken);

            if (string.IsNullOrEmpty(accessToken))
            {
                return true;
            }

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = handler.ReadJwtToken(accessToken);

            DateTime expirationThreshold = DateTime.UtcNow.Add(ExpirationThresholdDelta);

            return expirationThreshold > jwt.ValidTo;
        }

        private async Task<bool> RefreshTokensAsync(string scheme, bool useTokenLifetimeForTicket, AuthenticationProperties properties, CancellationToken cancellationToken)
        {
            string? refreshToken = properties.GetTokenValue(OpenIdConnectParameterNames.RefreshToken);

            if (string.IsNullOrEmpty(refreshToken))
            {
                throw new RefreshTokenNotFoundException();
            }

            try
            {
                TokenResponse tokenResponse = await OidcClient.RefreshTokenAsync(scheme, refreshToken, cancellationToken);

                DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn);

                if (useTokenLifetimeForTicket)
                {
                    properties.IssuedUtc = DateTimeOffset.UtcNow;
                    properties.ExpiresUtc = expiresAt;
                }

                properties.SetString(".sessionState", tokenResponse.SessionState);

                return properties.UpdateTokenValue(OpenIdConnectParameterNames.AccessToken, tokenResponse.AccessToken)
                    && properties.UpdateTokenValue(OpenIdConnectParameterNames.RefreshToken, tokenResponse.RefreshToken)
                    && properties.UpdateTokenValue(OpenIdConnectParameterNames.TokenType, tokenResponse.TokenType)
                    && properties.UpdateTokenValue("expires_at", expiresAt.ToString("r"));
            }
            catch (Exception e)
            {
                Logger.LogError(e, "Failed to refresh token for scheme '{scheme}'", scheme);
                return false;
            }
        }
    }
}
