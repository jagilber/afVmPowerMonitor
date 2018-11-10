using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;
using System;

namespace afVmPowerMonitor
{
    public static class Function
    {
        private static Program _program;

        /*
         * https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer
         * CRON expressions
            Azure Functions uses the NCronTab library to interpret CRON expressions. A CRON expression includes six fields:
            {second} {minute} {hour} {day} {month} {day-of-week}
            Each field can have one of the following types of values:
            Type    Example    When triggered
            A specific value    "0 5 * * * *"    at hh:05:00 where hh is every hour (once an hour)
            All values (*)    "0 * 5 * * *"    at 5:mm:00 every day, where mm is every minute of the hour (60 times a day)
            A range (- operator)    "5-7 * * * * *"    at hh:mm:05,hh:mm:06, and hh:mm:07 where hh:mm is every minute of every hour (3 times a minute)
            A set of values (, operator)    "5,8,10 * * * * *"    at hh:mm:05,hh:mm:08, and hh:mm:10 where hh:mm is every minute of every hour (3 times a minute)
            An interval value (/ operator)    "0 *\/5 * * * *"    at hh:05:00, hh:10:00, hh:15:00, and so on through hh:55:00 where hh is every hour (12 times an hour)

            $(SolutionDir)afVmPowerMonitor\func extensions install
            UseDevelopmentStorage=true

        */

        [FunctionName("Function")]
        public static void Run([TimerTrigger("%ScheduleAppSettings%")]TimerInfo myTimer, ILogger log) // for production run every 4 hours
        {
            if (_program == null)
            {
                _program = new Program(log);
            }

            _program.Execute();
        }
    }
}