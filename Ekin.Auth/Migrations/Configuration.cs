namespace Ekin.Auth.Migrations
{
    using Microsoft.AspNet.Identity.EntityFramework;
    using System.Data.Entity.Migrations;
    using System.Linq;

    internal sealed class Configuration : DbMigrationsConfiguration<AuthenticationDb>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
            ContextKey = "Ekin.Auth.AuthenticationDb";
        }

        protected override void Seed(AuthenticationDb db)
        {
            //  This method will be called after migrating to the latest version.
            Db.Operations repo = new Db.Operations(db);
            repo.InitializeClients();
            repo.InitializeRoles();

        }

        public async static void SetupClientsAndRoles()
        {
            using (Db.Operations repo = new Db.Operations())
            {
                await repo.InitializeClients();
                await repo.InitializeRoles();
            }
        }
    }
}
