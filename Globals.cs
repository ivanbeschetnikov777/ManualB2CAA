using System.Collections;
using System.Collections.Generic;

namespace ManualB2CAA
{
    public static class Globals
    {
        public const string TENANT = "aadb2ctudy";
        public const string POLICY = "B2C_1_signupsignin1";
        public const string CLIENT_ID = "36fc4f36-b357-4d96-b1b7-cf11c6765636";
        public const string ID_TOKEN = "id_token";
        public const string AUTH_CODE = "code";
        public const string GRANT_TYPE_AUTH_CODE = "authorization_code";
        public const string CLIENT_SECRET = "P64L0gxP2Xnb5cn~v3En-rI--B1r5c2QLt";
        public static string SCOPE = $"{Scopes.OPENID} {Scopes.OFFLINE_ACCESS}";
        public static string REDIRECT_URI = "https://localhost:44316/signin-oidc";
        public static string REDIRECT_URI_AUTH_CODE = "https://localhost:44316/code";
        public static string BASE_URI = $"https://{TENANT}.b2clogin.com/{TENANT}.onmicrosoft.com";
        public static string CODE_CHALLENGE = "YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmEyZGRhOGYyM2IzNjdmZWFhMTQ1ODg3NDcxY2Nl";
        public static string CODE_CHALLENGE_METHOD = "S256";
    }

    public static class Scopes
    {
        public const string OPENID = "openid";
        public const string OFFLINE_ACCESS = "offline_access";
    }

    public static class ResponsesMode
    {
        public const string FRAGMENT = "fragment";
        public const string FORM_POST = "form_post";
        public const string QUERY = "query";
    }

    public static class UriBuilder
    {
        public static string GetOidcAuthUrl()
        {
            return GetOidcBaseUri() +
                    "/oauth2/v2.0/authorize" +
                    $"?client_id={Globals.CLIENT_ID}" +
                    $"&response_type={Globals.ID_TOKEN}" +
                    $"&response_mode={ResponsesMode.FORM_POST}" +
                    $"&redirect_uri={Globals.REDIRECT_URI}" +
                    $"&scope={Globals.SCOPE}";
        }

        public static string GetAuthCodeUri(string code_challenge)
        {
            return GetOidcBaseUri() +
                   "/oauth2/v2.0/authorize" +
                   $"?client_id={Globals.CLIENT_ID}" +
                   $"&response_type={Globals.AUTH_CODE}" +
                   $"&response_mode={ResponsesMode.QUERY}" +
                   $"&redirect_uri={Globals.REDIRECT_URI_AUTH_CODE}" +
                   $"&scope=https://aadb2ctudy.onmicrosoft.com/1881f988-f0a2-4d84-9922-0a8da6550bb0/api.read" +
                   $"&code_challenge={code_challenge}" +
                   $"&code_challenge_method={Globals.CODE_CHALLENGE_METHOD}";
        }

        public static (string, IEnumerable<KeyValuePair<string, string>>) GetAccessTokenUrlWithBody(string code, string code_verifier)
        {
            var requestUri = GetOidcBaseUri() + "/oauth2/v2.0/token";
            var bodyParams = new List<KeyValuePair<string, string>>();

            bodyParams.Add(new KeyValuePair<string, string>("client_id", Globals.CLIENT_ID));
            bodyParams.Add(new KeyValuePair<string, string>("client_secret", Globals.CLIENT_SECRET));
            bodyParams.Add(new KeyValuePair<string, string>("grant_type", Globals.GRANT_TYPE_AUTH_CODE));
            bodyParams.Add(new KeyValuePair<string, string>("scope", $"{Globals.CLIENT_ID} offline_access"));
            bodyParams.Add(new KeyValuePair<string, string>("code", code));
            bodyParams.Add(new KeyValuePair<string, string>("redirect_uri", Globals.REDIRECT_URI_AUTH_CODE));
            bodyParams.Add(new KeyValuePair<string, string>("code_verifier", code_verifier));

            return (requestUri, bodyParams);
        }

        public static string GetOidcConfigurationUri()
        {
            return GetOidcBaseUri() + "/v2.0/.well-known/openid-configuration";
        }

        //public static string Get

        private static string GetOidcBaseUri()
        {
            return $"{Globals.BASE_URI}/{Globals.POLICY}";
        }
    }
}
