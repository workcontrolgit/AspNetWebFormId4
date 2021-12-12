using IdentityModel.Client;

using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;

using Owin;

using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AspNetWebFormImplicitFlow
{
    public partial class Startup
    {
        // These values are stored in Web.config. Make sure you update them!
        private readonly string _clientId = ConfigurationManager.AppSettings["Oidc:ClientId"];
        private readonly string _clientSecret = ConfigurationManager.AppSettings["Oidc:ClientSecret"];
        private readonly string _redirectUri = ConfigurationManager.AppSettings["Oidc:RedirectUri"];
        private readonly string _authority = ConfigurationManager.AppSettings["Oidc:Authority"];
        private readonly string _userInfoEndpoint = ConfigurationManager.AppSettings["Oidc:Authority"] + ConfigurationManager.AppSettings["Oidc:UserInfoEndpoint"];
        private readonly string _postLogoutRedirectUri = ConfigurationManager.AppSettings["Oidc:PostLogoutRedirectUri"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = "Cookies",
                ExpireTimeSpan = TimeSpan.FromMinutes(20),
                SlidingExpiration = true
            });

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "oidc",
                SignInAsAuthenticationType = "Cookies",
                Authority = _authority,
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                RedirectUri = _redirectUri,
                PostLogoutRedirectUri = _postLogoutRedirectUri,
                ProtocolValidator = new OpenIdConnectProtocolValidator
                {
                    RequireNonce = false,
                    RequireState = false,
                    RequireStateValidation = false
                },
                RedeemCode = true,
                RequireHttpsMetadata = false,       // for Development only!!!
                ResponseType = OpenIdConnectResponseType.Code,
                //SaveTokens = true,
                //ResponseMode = "query",
                Scope = "openid email",
                TokenValidationParameters = new TokenValidationParameters
                { 
                    NameClaimType = "name",
                },
                UseTokenLifetime = false,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = async n =>
                    {
                        var claims_to_exclude = new[]
                        {
                            "aud", "iss", "nbf", "exp", "nonce", "iat", "at_hash"
                        };

                        var claims_to_keep =
                            n.AuthenticationTicket.Identity.Claims
                            .Where(x => false == claims_to_exclude.Contains(x.Type)).ToList();
                        claims_to_keep.Add(new Claim("id_token", n.ProtocolMessage.IdToken));

                        if (n.ProtocolMessage.AccessToken != null)
                        {
                            claims_to_keep.Add(new Claim("access_token", n.ProtocolMessage.AccessToken));

                            var userInfoClient = new UserInfoClient(_userInfoEndpoint);
                            var userInfoResponse = await userInfoClient.GetAsync(n.ProtocolMessage.AccessToken);
                            var userInfoClaims = userInfoResponse.Claims
                                .Where(x => x.Type != "sub") // filter sub since we're already getting it from id_token
                                .Select(x => new Claim(x.Type, x.Value));
                            claims_to_keep.AddRange(userInfoClaims);
                        }

                        var ci = new ClaimsIdentity(
                            n.AuthenticationTicket.Identity.AuthenticationType,
                            "name", "role");
                        ci.AddClaims(claims_to_keep);

                        n.AuthenticationTicket = new Microsoft.Owin.Security.AuthenticationTicket(
                            ci, n.AuthenticationTicket.Properties
                        );
                    },
                    //RedirectToIdentityProvider = n =>
                    //{
                    //    if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                    //    {
                    //        // set PKCE parameters
                    //        var codeVerifier = CryptoRandom.CreateUniqueId(32);

                    //        string codeChallenge;
                    //        using (var sha256 = SHA256.Create())
                    //        {
                    //            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                    //            codeChallenge = Base64Url.Encode(challengeBytes);
                    //        }

                    //        n.ProtocolMessage.SetParameter("code_challenge", codeChallenge);
                    //        n.ProtocolMessage.SetParameter("code_challenge_method", "S256");

                    //        // remember code_verifier (adapted from OWIN nonce cookie)
                    //        RememberCodeVerifier(n, codeVerifier);
                    //    }

                    //    return Task.CompletedTask;
                    //},
                    //AuthorizationCodeReceived = n =>
                    //{
                    //    // get code verifier from cookie
                    //    // see: https://github.com/scottbrady91/Blog-Example-Classes/blob/master/AspNetFrameworkPkce/ScottBrady91.BlogExampleCode.AspNetPkce/Startup.cs#L102
                    //    var codeVerifier = RetrieveCodeVerifier(n);

                    //    // attach code_verifier on token request
                    //    n.TokenEndpointRequest.SetParameter("code_verifier", codeVerifier);

                    //    return Task.CompletedTask;
                    //},
                    //AuthorizationCodeReceived = async n =>
                    //{
                    //    // Exchange code for access and ID tokens
                    //    var tokenClient = new TokenClient(_tokenInfoEndpoint);

                    //    var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, _redirectUri);
                    //    if (tokenResponse.IsError)
                    //    {
                    //        throw new Exception(tokenResponse.Error);
                    //    }

                    //    var userInfoClient = new UserInfoClient(_userInfoEndpoint);
                    //    var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                    //    var claims = new List<Claim>(userInfoResponse.Claims)
                    //    {
                    //        new Claim("id_token", tokenResponse.IdentityToken),
                    //        new Claim("access_token", tokenResponse.AccessToken)
                    //    };

                    //    n.AuthenticationTicket.Identity.AddClaims(claims);
                    //},
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var id_token = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                            n.ProtocolMessage.IdTokenHint = id_token;
                        }

                        return Task.CompletedTask;
                    }
                },
            });
            app.UseStageMarker(PipelineStage.Authenticate);
        }
        private void RememberCodeVerifier(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string codeVerifier)
        {
            var properties = new AuthenticationProperties();
            properties.Dictionary.Add("cv", codeVerifier);
            n.Options.CookieManager.AppendResponseCookie(
                n.OwinContext,
                GetCodeVerifierKey(n.ProtocolMessage.State),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(n.Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure,
                    Expires = DateTime.UtcNow + n.Options.ProtocolValidator.NonceLifetime
                });
        }
        private string RetrieveCodeVerifier(AuthorizationCodeReceivedNotification n)
        {
            string key = GetCodeVerifierKey(n.ProtocolMessage.State);

            string codeVerifierCookie = n.Options.CookieManager.GetRequestCookie(n.OwinContext, key);
            if (codeVerifierCookie != null)
            {
                var cookieOptions = new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure
                };

                n.Options.CookieManager.DeleteCookie(n.OwinContext, key, cookieOptions);
            }

            var cookieProperties = n.Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(codeVerifierCookie)));
            cookieProperties.Dictionary.TryGetValue("cv", out var codeVerifier);

            return codeVerifier;
        }
        private string GetCodeVerifierKey(string state)
        {
            using (var hash = SHA256.Create())
            {
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + "cv." + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(state)));
            }
        }
    }
}