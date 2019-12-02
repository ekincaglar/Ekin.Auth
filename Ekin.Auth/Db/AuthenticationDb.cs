using Ekin.Auth.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;
using System.Linq;
using System.Web;

namespace Ekin.Auth
{
    [DbConfigurationType(typeof(Ekin.Auth.Db.Configuration))]
    public class AuthenticationDb : IdentityDbContext<IdentityUser>
    {
        public AuthenticationDb() : base(Settings.ConnectionString)
        {
            // Set the database intializer which is run once during application start
            // This seeds the database with admin user credentials and admin role
            Database.SetInitializer(new AuthenticationDbInitializer());
        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        //protected override void OnModelCreating(DbModelBuilder modelBuilder)
        //{
        //    modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
        //}

    }

}