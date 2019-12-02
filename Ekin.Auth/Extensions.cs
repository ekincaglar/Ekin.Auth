using Ekin.Auth.Models;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;

namespace Ekin.Auth
{
    public static class Extensions
    {
        public static AuthRequest GetAuthRequest(this BaseValidatingContext<OAuthAuthorizationServerOptions> context)
        {
            if (context == null || context.Request == null)
                return null;

            Stream req = context.Request.Body;
            req.Seek(0, System.IO.SeekOrigin.Begin);
            string json = new StreamReader(req).ReadToEnd();
            AuthRequest authRequest = null;
            try
            {
                authRequest = JsonConvert.DeserializeObject<AuthRequest>(json);
                return authRequest;
            }
            catch
            {
                return null;
            }
        }

    }
}