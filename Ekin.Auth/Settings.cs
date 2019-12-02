using Ekin.Auth.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Ekin.Auth
{
    public static class Settings
    {
        public static string ConnectionString { get; set; }
        public static bool UseSqlAzure { get; set; } = false;
        public static bool AllowInsecureHttp { get; set; } = false;

        public static bool UseEmailAsUsername { get; set; } = true;   // DO NOT change this once the database is populated

        public static Ekin.Email.IEmailClient EmailClient { get; set; }
        public static Ekin.Email.EmailMessage PasswordReset { get; set; }
        public static Ekin.Email.EmailMessage EmailVerification { get; set; }

        public static bool FacebookEnabled { get; set; } = false;
        public static string FacebookAppId { get; set; }
        public static string FacebookAppSecret { get; set; }
        /// <summary>
        /// You can get the FacebookAppToken from here: https://developers.facebook.com/tools/accesstoken/
        /// More about debug_tokn here: http://stackoverflow.com/questions/16641083/how-does-one-get-the-app-access-token-for-debug-token-inspection-on-facebook
        /// </summary>
        public static string FacebookAppToken { get; set; }
        public static string FacebookUserToken { get; set; }    // NOT USED

        public static bool GoogleEnabled { get; set; } = false;
        public static string GoogleClientId { get; set; }
        public static string GoogleClientSecret { get; set; }

        public static string TokenEndpointPath { get; set; } = "/token";
        public static int TokenExpiresInMinutes { get; set; } = 30;

        public static List<string> Roles { get; set; } = new List<string> { "User", "Company Admin", "Private Label Admin", "System Admin" };
        public static string DefaultUserRole { get; set; } = "User";
        public static string DefaultAdminRole { get; set; } = "System Admin";

        public static bool CreateDefaultAdmin { get; set; } = true;
        public static string DefaultAdminUsername { get; set; } = "admin";
        public static string DefaultAdminPassword { get; set; } = "AdminPass1";
        public static string DefaultAdminEmail { get; set; } = "admin@ekin.co";

        public static string AppName { get; set; }

        private static List<Client> _clients { get; set; }
        public static List<Client> Clients
        {
            get
            {
                if (_clients == null)
                {
                    _clients = new List<Client>
                    {
                        new Client
                        { Id = "mainApp",
                            Secret= Helper.GetHash("abc@123"),
                            Name="Main Application",
                            ApplicationType =  Models.ApplicationTypes.JavaScript,
                            Active = true,
                            RefreshTokenLifeTime = 7200,
                            AllowedOrigin = "*"
                        },
                        new Client
                        { Id = "consoleApp",
                            Secret=Helper.GetHash("123@abc"),
                            Name="Console Application",
                            ApplicationType = Models.ApplicationTypes.NativeConfidential,
                            Active = true,
                            RefreshTokenLifeTime = 14400,
                            AllowedOrigin = "*"
                        }
                    };
                }
                return _clients;
            }
            set
            {
                _clients = value;
            }
        }

    }
}