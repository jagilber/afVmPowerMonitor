namespace afVmPowerMonitor
{
    public class VmssInstanceResults
    {
        public Extensions[] extensions;
        public Statuses[] statuses;
        public VirtualMachine virtualMachine = new VirtualMachine();

        public class Extensions
        {
            public string name;
            public StatusesSummary[] statusesSummaries;
        }

        public class Statuses
        {
            public string code;
            public string displayStatus;
            public string level;
            public string time;
        }

        public class StatusesSummary
        {
            public string code;
            public int count;
        }

        public class VirtualMachine
        {
            public StatusesSummary[] statusesSummary;
        }
    }
}