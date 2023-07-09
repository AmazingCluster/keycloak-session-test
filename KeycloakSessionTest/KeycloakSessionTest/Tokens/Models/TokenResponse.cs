﻿using System.Text.Json.Serialization;

namespace KeycloakSessionTest.Tokens.Models
{
    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = default!;

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; } = default!;

        [JsonPropertyName("refresh_expires_in")]
        public int RefreshExpiresIn { get; set; } = default!;

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = default!;

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = default!;

        [JsonPropertyName("id_token")]
        public string IdToken { get; set; } = default!;

        [JsonPropertyName("not-before-policy")]
        public int NotBeforePolicy { get; set; } = default!;

        [JsonPropertyName("session_state")]
        public string SessionState { get; set; } = default!;

        [JsonPropertyName("scope")]
        public string Scope { get; set; } = default!;
    }
}
