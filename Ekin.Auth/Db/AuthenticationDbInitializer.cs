using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace Ekin.Auth
{
    public class AuthenticationDbInitializer : CreateDatabaseIfNotExists<AuthenticationDb>
    {
        protected override void Seed(AuthenticationDb db)
        {
            base.Seed(db);
            InitializeIdentityForEF(db);
        }

        public async static void InitializeIdentityForEF(AuthenticationDb db)
        {
            using (Db.Operations repo = new Db.Operations(db))
            {
                await repo.InitializeClients();
                await repo.InitializeRoles();
            }
        }
    }
}
