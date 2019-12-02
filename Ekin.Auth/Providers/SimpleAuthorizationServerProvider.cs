using Ekin.Auth.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Ekin.Auth.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
       public SimpleAuthorizationServerProvider()
        {
            //OnValidateClientAuthentication
            //OnGrantResourceOwnerCredentials
            //OnGrantRefreshToken
            //OnAuthorizationEndpointResponse
            //OnAuthorizeEndpoint
            //OnGrantAuthorizationCode
            //OnGrantClientCredentials
            //OnGrantCustomExtension
            //OnMatchEndpoint
            //OnTokenEndpoint
            //OnTokenEndpointResponse
            //OnValidateAuthorizeRequest
            //OnValidateClientRedirectUri
            //OnValidateTokenRequest
        }

        /// <summary>
        /// The route of this method is defined by Settings.TokenEndpointPath endpoint, e.g. /token
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Called to validate that the origin of the request is a registered "client_id", and that the correct credentials for that 
            // client are present on the request. If the web application accepts Basic authentication credentials, 
            // context.TryGetBasicCredentials(out clientId, out clientSecret) may be called to acquire those values if present in the request header. 
            // If the web application accepts "client_id" and "client_secret" as form encoded POST parameters, 
            // context.TryGetFormCredentials(out clientId, out clientSecret) may be called to acquire those values if present in the request body. 
            // If context.Validated is not called the request will not proceed further.

            string clientId = string.Empty;
            string clientSecret = string.Empty;

            #region Load ClientId and ClientSecret from the request

            bool BodyAuthentication = false;
            bool HeaderAuthentication = false;

            BodyAuthentication = context.TryGetFormCredentials(out clientId, out clientSecret);
            if (!BodyAuthentication)
            {
                HeaderAuthentication = context.TryGetBasicCredentials(out clientId, out clientSecret);
                if (!HeaderAuthentication)
                {
                    AuthRequest authRequest = context.GetAuthRequest();
                    if (authRequest != null)
                    {
                        clientId = authRequest.client_id;
                        clientSecret = authRequest.client_secret;
                    }
                }
            }
            
            if (string.IsNullOrWhiteSpace(clientId))
            {
                // Remove the comments from the below lines if you want to force sending clientId/secrects 
                // once access token is obtained
                context.Rejected();
                context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            #endregion

            Client client = null;

            #region Validate Client from the database

            using (Db.Operations _repo = new Db.Operations())
            {
                client = _repo.FindClient(clientId);
            }

            if (client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", clientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == Models.ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError("invalid_clientId", "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            #endregion

            context.OwinContext.Set<string>("as:clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            context.Validated(clientId);  // This sets context.ClientId parameter
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// GrantResourceOwnerCredentials is used to validate provided username and password when the grant_type is set to password
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            ClaimsIdentity identity = null;

            using (Db.Operations _repo = new Db.Operations())
            {
                IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }

                IList<string> roles = await _repo.UserRoles(user.Id);
                identity = new ClaimsIdentity(context.Options.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
                foreach (string role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
                //identity.AddClaim(new Claim("sub", context.UserName));
            }

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { 
                        "as:client_id", (context.ClientId == null) ? string.Empty : context.ClientId
                    },
                    { 
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);
        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            
            var newClaim = newIdentity.Claims.Where(c => c.Type == "newClaim").FirstOrDefault();
            if (newClaim != null)
            {
                newIdentity.RemoveClaim(newClaim);
            }
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Called at the final stage of a successful Token endpoint request. An application may implement this call in order to do any final modification of the claims being used to issue access or refresh tokens. This call may also be used in order to add additional response parameters to the Token endpoint's json response body.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        //public Task GrantAuthorizationCode(OAuthGrantAuthorizationCodeContext context)
        //{
        //    return Task.FromResult(new NotImplementedException());
        //}

        //public Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        //{
        //    return Task.FromResult(new NotImplementedException());
        //}
        
        //public override Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        //{
        //    return Task.FromResult(new NotImplementedException());
        //}

        //public override Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        //{
        //    return Task.FromResult(new NotImplementedException());
        //}

        //public override Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        //{
        //    if (context.GrantType != "password")
        //    {
        //        var claims = new List<Claim>();
        //        claims.Add(new Claim("grant_type", context.GrantType));
        //        claims.Add(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Parameters["alias"]));
        //        context.Validated(new ClaimsIdentity(claims, "Bearer"));
        //        return Task.FromResult<object>(null);
        //    }
        //    else
        //    {
        //        context.SetError("invalid_grant", "unsupported_grant_type");
        //        return Task.FromResult<object>(null);
        //    }
        //}
    }
}