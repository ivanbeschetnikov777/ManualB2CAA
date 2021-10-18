using Microsoft.AspNetCore.Mvc;
using Newton = Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ManualB2CAA.Controllers
{
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private static string cv;

        public AuthController(HttpClient client)
        {
            Client = client;
        }

        public HttpClient Client { get; }

        [HttpGet("login")]
        public IActionResult Login()
        {
            return Redirect(UriBuilder.GetOidcAuthUrl());
        }

        [HttpGet("acquire-code")]
        public IActionResult AcquireCode()
        {
            var cvBytes = IdTokenVerifier.GetNewCodeVerifierInBytes();
            cv = IdTokenVerifier.GetCodeVerifier(cvBytes);
            var ch = IdTokenVerifier.GetCodeChallange(cv);

            return Redirect(UriBuilder.GetAuthCodeUri(ch));
        }

        [HttpPost("~/signin-oidc")]
        public async Task<IActionResult> SignIn()
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(Request.Form["id_token"]);

            var config = await SendAsync<OAuthConfig>(UriBuilder.GetOidcConfigurationUri());
            var keys = await SendAsync<OAuthKeys>(config.JwksUri);

            var isValid = IdTokenVerifier.IsValid(token.RawData, keys.Keys[0].E, keys.Keys[0].N);

            return isValid
                ? View("Auth", Newton.JsonConvert.SerializeObject(config, Newton.Formatting.Indented))
                : View("Auth", "invalid token");
        }

        [HttpGet("~/code")]
        public async Task<IActionResult> Code([FromQuery] string code)
        {
            var (url, body) = UriBuilder.GetAccessTokenUrlWithBody(code, cv);
            return await GetAccessToken(url, body);
        }

        private async Task<IActionResult> GetAccessToken(string url, dynamic body)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url);

            using (var content = new FormUrlEncodedContent(body))
            {
                request.Content = content;
                request.Content.Headers.Clear();
                request.Content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");

                var response = await Client.SendAsync(request);
                using (var reader = new StreamReader(response.Content.ReadAsStream()))
                {
                    return View("Auth", Newton.JsonConvert.SerializeObject(reader.ReadToEnd(), Newton.Formatting.Indented));
                }
            }
        }

        private async Task<T> SendAsync<T>(string url)
        {
            var response = await Client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));

            if (response.IsSuccessStatusCode)
            {
                var contentStream = await response.Content.ReadAsStreamAsync();
                var config = await JsonSerializer.DeserializeAsync<T>(contentStream, new JsonSerializerOptions() { PropertyNameCaseInsensitive = true, });

                return config;
            }

            return default;
        }
    }

    public static class IdTokenVerifier
    {
        private static readonly Random _rnd = new();

        public static bool IsValid(string token, string exponenta, string modulus)
        {
            var tokenParts = token.Split('.');
            var rsa = new RSACryptoServiceProvider();

            rsa.ImportParameters(new RSAParameters()
            {
                Exponent = FromBase64Url(exponenta),
                Modulus = FromBase64Url(modulus)
            });

            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            var deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm(nameof(SHA256));
            return deformatter.VerifySignature(hash, FromBase64Url(tokenParts[2]));
        }

        public static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        public static string GetCodeVerifier(byte[] data)
        {
            var code_verifier = Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            return code_verifier;
        }

        public static string GetCodeChallange(string code_verifier)
        {
            var code_challange = string.Empty;
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(code_verifier));
                code_challange = Convert.ToBase64String(challengeBytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }

            return code_challange;
        }

        public static byte[] GetNewCodeVerifierInBytes()
        {
            var bytes = new byte[32];
            _rnd.NextBytes(bytes);
            return bytes;
        }
    }

    public class OAuthConfig
    {
        public string Issuer { get; set; }

        [JsonPropertyName("authorization_endpoint")]
        public string AuthorizationEndpoint { get; set; }

        [JsonPropertyName("jwks_uri")]
        public string JwksUri { get; set; }

    }

    public class OAuthKeys
    {
        public OAuthKeysModel[] Keys { get; set; }
    }

    public class OAuthKeysModel
    {
        public string Kid { get; set; }
        public long Nbf { get; set; }
        public string E { get; set; }
        public string N { get; set; }
    }
}
