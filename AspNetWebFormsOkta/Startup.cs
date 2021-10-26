using IdentityModel.Client;

using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

using Owin;

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(AspNetWebFormsOkta.Startup))]

namespace AspNetWebFormsOkta
{
    public class Startup
    {
        // These values are stored in Web.config. Make sure you update them!
        private readonly string _clientId = ConfigurationManager.AppSettings["Oidc:ClientId"];

        private readonly string _redirectUri = ConfigurationManager.AppSettings["Oidc:RedirectUri"];
        private readonly string _authority = ConfigurationManager.AppSettings["Oidc:Authority"];
        private readonly string _userInfoEndpoint = ConfigurationManager.AppSettings["Oidc:Authority"] + ConfigurationManager.AppSettings["Oidc:UserInfoEndpoint"];
        private readonly string _tokenInfoEndpoint = ConfigurationManager.AppSettings["Oidc:Authority"] + ConfigurationManager.AppSettings["Oidc:TokenInfoEndpoint"];
        private readonly string _clientSecret = ConfigurationManager.AppSettings["Oidc:ClientSecret"];
        private readonly string _postLogoutRedirectUri = ConfigurationManager.AppSettings["Oidc:PostLogoutRedirectUri"];

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = "Cookies",
                ExpireTimeSpan = TimeSpan.FromMinutes(10),
                SlidingExpiration = true
            });

            var openidConfiguration = OpenIdConnectConfigurationRetriever.GetAsync(
                        $"{_authority}/.well-known/openid-configuration", CancellationToken.None);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                Authority = _authority,
                RedirectUri = _redirectUri,
                PostLogoutRedirectUri = _postLogoutRedirectUri,
                ResponseType = OpenIdConnectResponseType.IdTokenToken,
                Scope = OpenIdConnectScope.OpenIdProfile,
                //ProtocolValidator = new OpenIdConnectProtocolValidator()
                //    {
                //                        RequireNonce = true
                //                                       },
                MetadataAddress = "https://localhost:44310/.well-known/openid-configuration",
                TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    //AuthenticationFailed = OnAuthenticationFailed,
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
                            //var userInfoClaims = userInfoResponse.Claims;
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
                    AuthorizationCodeReceived = async n =>
                    {
                        // Exchange code for access and ID tokens
                        var tokenClient = new TokenClient(_tokenInfoEndpoint, _clientId, _clientSecret);

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, _redirectUri);
                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        //var userInfoClient = new UserInfoClient(_userInfoEndpoint);
                        var userInfoClient = new UserInfoClient(_userInfoEndpoint);
                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                        var claims = new List<Claim>(userInfoResponse.Claims)
                        {
                            new Claim("id_token", tokenResponse.IdentityToken),
                            new Claim("access_token", tokenResponse.AccessToken)
                        };

                        n.AuthenticationTicket.Identity.AddClaims(claims);
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var id_token = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                            n.ProtocolMessage.IdTokenHint = id_token;
                        }

                        return Task.FromResult(0);
                    }
                },
            });
        }

        //private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        //{
        //    context.HandleResponse();
        //    context.Response.Redirect("/?errormessage=" + context.Exception.Message);
        //    return Task.FromResult(0);
        //}

    }
}