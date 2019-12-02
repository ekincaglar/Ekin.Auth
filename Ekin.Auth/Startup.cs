using Ekin.Auth.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;
using Owin;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Net.Http.Formatting;
using System.Security.Claims;
using System.Web;
using System.Web.Http;

[assembly: OwinStartup(typeof(Ekin.Auth.Startup))]
namespace Ekin.Auth
{

    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static GoogleOAuth2AuthenticationOptions googleAuthOptions { get; private set; }
        public static FacebookAuthenticationOptions facebookAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);
            HttpConfiguration config = new HttpConfiguration();
            WebApiConfigRegister(config);
            var jsonFormatter = config.Formatters.OfType<JsonMediaTypeFormatter>().First();
            jsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(config);

            //Database.SetInitializer(new AuthenticationDbInitializer());
            Database.SetInitializer(new MigrateDatabaseToLatestVersion<AuthenticationDb, Migrations.Configuration>());
            //Migrations.Configuration.SetupClientsAndRoles();
        }

        public void WebApiConfigRegister(HttpConfiguration config)
        {
            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            //use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions() {
                AllowInsecureHttp = Settings.AllowInsecureHttp,
                TokenEndpointPath = new PathString(Settings.TokenEndpointPath),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(Settings.TokenExpiresInMinutes),
                Provider = new SimpleAuthorizationServerProvider(),
                RefreshTokenProvider = new SimpleRefreshTokenProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);

            if (Settings.GoogleEnabled)
            {
                //Configure Google External Login
                googleAuthOptions = new GoogleOAuth2AuthenticationOptions()
                {
                    ClientId = Settings.GoogleClientId,
                    ClientSecret = Settings.GoogleClientSecret,
                    Provider = new GoogleAuthProvider()
                };
                app.UseGoogleAuthentication(googleAuthOptions);
            }

            if (Settings.FacebookEnabled)
            {
                //Configure Facebook External Login
                facebookAuthOptions = new FacebookAuthenticationOptions()
                {
                    AppId = Settings.FacebookAppId,
                    AppSecret = Settings.FacebookAppSecret,
                    Provider = new FacebookAuthProvider()
                };
                app.UseFacebookAuthentication(facebookAuthOptions);
            }

        }

    }

}