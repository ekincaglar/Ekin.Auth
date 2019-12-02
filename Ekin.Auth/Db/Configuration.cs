using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.Entity.SqlServer;

namespace Ekin.Auth.Db
{
    public class Configuration : DbConfiguration
    {
        public Configuration()
        {
            if (Settings.UseSqlAzure)
            {
                // Default execution strategy is DefaultSqlExecutionStrategy and doesn't include retries
                SetExecutionStrategy("System.Data.SqlClient", () => new SqlAzureExecutionStrategy());

                SetDefaultConnectionFactory(new LocalDbConnectionFactory("v11.0"));
            }
        }
    }
}