using Microsoft.Azure.Management.ResourceManager.Models;

namespace afVmPowerMonitor
{
    public class KustoClusterResults
    {
        public string name;
        public string type;
        public string id;
        public string location;
        public Properties properties = new Properties();
        public Sku sku = new Sku();
        public TrustedExternalTenants[] trustedExternalTenants;

        public class Properties
        {
            public string state;
            public string queryUri;
            public string dataIngestionUri;
        }

        public class Sku
        {
            public string name;
            public string tier;
            public int capacity;
        }

        public class TrustedExternalTenants
        {
            public string value;
        }
    }
}