namespace afVmPowerMonitor
{
    public class VMInstanceResults
    {
        public string computerName;
        public string location;
        public string osName;
        public string osVersion;
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