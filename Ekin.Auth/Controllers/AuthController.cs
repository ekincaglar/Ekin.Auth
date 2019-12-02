using Ekin.Auth.Results;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using Ekin.Auth.Models;
using System.Net.Mail;
using Ekin.Email;

namespace Ekin.Auth.Controllers
{
    [RoutePrefix("Auth")]
    public class AuthController : ApiController
    {
        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        public AuthController()
        {
            
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("Test")]
        public async Task<IHttpActionResult> Test()
        {
            using (Db.Operations db = new Db.Operations())
            {
                Client client = db.FindClient("mainApp");
                return Ok("Client found. Allowed origin: " + client.AllowedOrigin);
            }
        }

        // POST Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(AspNetUser userModel)
        {
            if (userModel == null)
            {
                return BadRequest("User data is empty - cannot register user");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            else if (Settings.UseEmailAsUsername && String.IsNullOrWhiteSpace(userModel.Email))
            {
                return BadRequest("Email must be provided");
            }
            else if (!Settings.UseEmailAsUsername && String.IsNullOrWhiteSpace(userModel.UserName))
            {
                return BadRequest("Username must be provided");
            }

            IHttpActionResult errorResult = null;

            using (Db.Operations ops = new Db.Operations())
            {
                IdentityUser idUser = new IdentityUser()
                {
                    UserName = Settings.UseEmailAsUsername ? userModel.Email : userModel.UserName,
                    Email = userModel.Email,
                    EmailConfirmed = false,
                    PhoneNumber = userModel.PhoneNumber,
                    PhoneNumberConfirmed = false,
                    TwoFactorEnabled = false
                };
                IdentityResult result = await ops.RegisterUser(idUser, userModel.Password);
                errorResult = GetErrorResult(result);
                if (errorResult != null)
                {
                    return errorResult;
                }
                else
                {
                    userModel.IdentityUserId = idUser.Id;
                }
            }

            return Ok();
        }

        // GET Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            string redirectUri = string.Empty;

            if (error != null)
            {
                return BadRequest(Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            var redirectUriValidationResult = ValidateClientAndRedirectUri(this.Request, ref redirectUri);

            if (!string.IsNullOrWhiteSpace(redirectUriValidationResult))
            {
                return BadRequest(redirectUriValidationResult);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            IdentityUser user = null;

            using (Db.Operations ops = new Db.Operations())
            {
                user = await ops.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));
            }

            bool hasRegistered = user != null;

            redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&haslocalaccount={3}&external_user_name={4}",
                                            redirectUri,
                                            externalLogin.ExternalAccessToken,
                                            externalLogin.LoginProvider,
                                            hasRegistered.ToString(),
                                            externalLogin.UserName);

            return Redirect(redirectUri);

        }

        // POST Account/RegisterExternal
        [AllowAnonymous]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var verifiedAccessToken = await VerifyExternalAccessToken(model.Provider, model.ExternalAccessToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            using (Db.Operations ops = new Db.Operations())
            {
                IdentityUser user = await ops.FindAsync(new UserLoginInfo(model.Provider, verifiedAccessToken.user_id));

                bool hasRegistered = user != null;

                if (hasRegistered)
                {
                    return BadRequest("External user is already registered");
                }

                user = new IdentityUser() { UserName = model.UserName };    // TODO: We will need other fields in the User object

                IdentityResult result = await ops.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }

                var info = new ExternalLoginInfo()
                {
                    DefaultUserName = model.UserName,
                    Login = new UserLoginInfo(model.Provider, verifiedAccessToken.user_id)
                };

                result = await ops.AddLoginAsync(user.Id, info.Login);
                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(model.UserName);

            return Ok(accessTokenResponse);
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ObtainLocalAccessToken")]
        public async Task<IHttpActionResult> ObtainLocalAccessToken(string provider, string externalAccessToken)
        {

            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(externalAccessToken))
            {
                return BadRequest("Provider or external access token is not sent");
            }

            var verifiedAccessToken = await VerifyExternalAccessToken(provider, externalAccessToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            IdentityUser user = null;

            using (Db.Operations ops = new Db.Operations())
            {
                user = await ops.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));
            }

            bool hasRegistered = user != null;

            if (!hasRegistered)
            {
                return BadRequest("External user is not registered");
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(user.UserName);

            return Ok(accessTokenResponse);

        }

        [AllowAnonymous]
        [Route("PasswordResetRequest")]
        [HttpGet]
        public async Task<IHttpActionResult> PasswordResetRequest(string email)
        {
            IdentityUser idUser = null;

            using (Db.Operations ops = new Db.Operations())
            {
                idUser = await ops.FindUserByEmail(email);

                if (idUser != null)
                {
                    try
                    {
                        // For the Password Reset Token to work:
                        // Go to the Application Pool for the web site in IIS
                        // Advanced Settings > Process Model > Load User Profile = True
                        string resetToken = await ops.GetPasswordResetToken(idUser.Id);

                        if (Settings.EmailClient != null && Settings.PasswordReset != null)
                        {
                            EmailMessage mailMessage = Settings.PasswordReset;
                            mailMessage.To = new EmailAddress(email);
                            mailMessage.PlainTextContent = mailMessage.PlainTextContent.Replace("{EmailAddress}", email).Replace("{Token}", HttpUtility.UrlEncode(resetToken));
                            mailMessage.HtmlContent = mailMessage.HtmlContent.Replace("{EmailAddress}", email).Replace("{Token}", HttpUtility.UrlEncode(resetToken));
                            await Settings.EmailClient.SendAsync(mailMessage);
                        }

                        return Ok();
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(string.Format("Password reset details could not be sent to {0}. Internal error: {1}", email, ex.Message));
                    }
                }
            }

            return Ok();
        }

        [AllowAnonymous]
        [Route("PasswordReset")]
        [HttpPost]
        public async Task<IHttpActionResult> PasswordReset(PasswordResetModel pwd)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityUser idUser = null;

            using (Db.Operations ops = new Db.Operations())
            {
                idUser = await ops.FindUserByEmail(pwd.Email);

                if (idUser != null)
                {
                    IdentityResult result = await ops.ResetPasswordAsync(idUser.Id, pwd.Token, pwd.Password);
                    if (!result.Succeeded)
                    {
                        if (result.Errors != null && result.Errors.Count() > 0)
                        {
                            return Redirect(pwd.FailUrl + "?error=" + GetErrorString(result));
                        }
                    }
                    else
                    {
                        return Redirect(pwd.SuccessUrl);
                    }
                }
            }

            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                //_repo.Dispose();
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private string GetErrorString(IdentityResult result)
        {
            string ret = "";
            
            if (result != null && !result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        if (!string.IsNullOrWhiteSpace(ret)) ret += ", ";
                        ret += error;
                    }
                }
            }

            return ret;
        }

        private string ValidateClientAndRedirectUri(HttpRequestMessage request, ref string redirectUriOutput)
        {

            Uri redirectUri;

            var redirectUriString = GetQueryString(Request, "redirect_uri");

            if (string.IsNullOrWhiteSpace(redirectUriString))
            {
                return "redirect_uri is required";
            }

            bool validUri = Uri.TryCreate(redirectUriString, UriKind.Absolute, out redirectUri);

            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            var clientId = GetQueryString(Request, "client_id");

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return "client_Id is required";
            }

            Client client = null;

            using (Db.Operations ops = new Db.Operations())
            {
                client = ops.FindClient(clientId);
            }

            if (client == null)
            {
                return string.Format("Client_id '{0}' is not registered in the system.", clientId);
            }

            if (!string.Equals(client.AllowedOrigin, redirectUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
            {
                return string.Format("The given URL is not allowed by Client_id '{0}' configuration.", clientId);
            }

            redirectUriOutput = redirectUri.AbsoluteUri;

            return string.Empty;

        }

        private string GetQueryString(HttpRequestMessage request, string key)
        {
            var queryStrings = request.GetQueryNameValuePairs();

            if (queryStrings == null) return null;

            var match = queryStrings.FirstOrDefault(keyValue => string.Compare(keyValue.Key, key, true) == 0);

            if (string.IsNullOrEmpty(match.Value)) return null;

            return match.Value;
        }

        private async Task<ParsedExternalAccessToken> VerifyExternalAccessToken(string provider, string accessToken)
        {
            ParsedExternalAccessToken parsedToken = null;

            var verifyTokenEndPoint = "";

            if (provider == "Facebook")
            {
                var appToken = Settings.FacebookAppToken;
                verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", accessToken, appToken);
            }
            else if (provider == "Google")
            {
                verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}", accessToken);
            }
            else
            {
                return null;
            }

            var client = new HttpClient();
            var uri = new Uri(verifyTokenEndPoint);
            var response = await client.GetAsync(uri);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                dynamic jObj = (JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);

                parsedToken = new ParsedExternalAccessToken();

                if (provider == "Facebook")
                {
                    parsedToken.user_id = jObj["data"]["user_id"];
                    parsedToken.app_id = jObj["data"]["app_id"];

                    if (!string.Equals(Startup.facebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }
                }
                else if (provider == "Google")
                {
                    parsedToken.user_id = jObj["user_id"];
                    parsedToken.app_id = jObj["audience"];

                    if (!string.Equals(Startup.googleAuthOptions.ClientId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                }

            }

            return parsedToken;
        }

        private JObject GenerateLocalAccessTokenResponse(string userName)
        {

            var tokenExpiration = TimeSpan.FromDays(1);

            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            identity.AddClaim(new Claim("role", "user"));

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);

            var accessToken = Startup.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);

            // TODO: Serialise LoginResponse object
            JObject tokenResponse = new JObject(
                                        new JProperty("userName", userName),
                                        new JProperty("access_token", accessToken),
                                        new JProperty("token_type", "bearer"),
                                        new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
                                        new JProperty(".issued", ticket.Properties.IssuedUtc.ToString()),
                                        new JProperty(".expires", ticket.Properties.ExpiresUtc.ToString())
        );

            return tokenResponse;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }
            public string ExternalAccessToken { get; set; }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer) || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name),
                    ExternalAccessToken = identity.FindFirstValue("ExternalAccessToken"),
                };
            }
        }

        #endregion
    }
}
