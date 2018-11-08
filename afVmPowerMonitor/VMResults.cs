namespace afVmPowerMonitor
{
    public class VMResults
    {
        public string id;
        public string location;
        public string name;
        public Properties properties = new Properties();
        public string type;

        public class HardwareProfile
        {
            public string vmSize;
        }

        public class Properties
        {
            public HardwareProfile hardwareProfile = new HardwareProfile();
            public string provisioningState;
            public string vmId;
        }
    }
}