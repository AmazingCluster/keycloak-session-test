using Microsoft.AspNetCore.Authentication;

namespace KeycloakSessionTest.Tokens.Exceptions
{
    public class RefreshTokenNotFoundException : Exception
    {
        public RefreshTokenNotFoundException() : base(GetMessage())
        {
        }

        private static string? GetMessage()
        {
            return $"No refresh token could be found in the {typeof(AuthenticationProperties).Name}";
        }
    }
}
