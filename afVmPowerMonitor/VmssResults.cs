namespace afVmPowerMonitor
{
    public class VmssResults
    {
        public Sku sku = new Sku();
        public Properties properties = new Properties();
        public string type;
        public string location;
        public Tags tags = new Tags();
        public string id;
        public string name;

        public class Tags
        {
            public string reourceType;
            public string clusterName;
        }

        public class Properties
        {
            public bool singlePlacementGroup;
            public UpgradePolicy upgradePolicy = new UpgradePolicy();
            public VirtualMachineProfile virtualMachineProfile = new VirtualMachineProfile();
            public string provisioningState;
            public bool overprovision;
            public string uniqueId;
        }

        public class VirtualMachineProfile
        {
            private OSProfile oSProfile = new OSProfile();
        }

        public class OSProfile
        {
            public string computerNamePrefix;
            public string adminUserName;
            public LinuxConfiguration linuxConfiguration = new LinuxConfiguration();
            public Secrets[] secrets;
        }

        public class Secrets
        {
        }

        public class LinuxConfiguration
        {
            public string disablePasswordAuthentication;
        }

        public class UpgradePolicy
        {
            public string mode;
            public bool automaticUpgrade;
        }

        public class Sku
        {
            public string name;
            public string tier;
            public int capacity;
        }
    }
}