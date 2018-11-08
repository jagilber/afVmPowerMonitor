namespace afVmPowerMonitor
{
    public class VmssVMInstanceResults
    {
        // added properties
        public string id;
        public string name;
        public string type;
        public int instanceId;

        public string placementGroupId;
        public int platformFaultDomain;
        public int platformUpdateDomain;
        public Statuses[] statuses;

        public class Statuses
        {
            public string code;
            public string displayStatus;
            public string level;
            public string time;
        }
    }
}