using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Threading;

namespace Powerless
{
    public class Program
    {
        public static int run(String pwzArgument)
        {
            using (PowerShell PowerShellInstance = PowerShell.Create())
            {
                PowerShellInstance.AddScript(pwzArgument);
                IAsyncResult result = PowerShellInstance.BeginInvoke();
                while (result.IsCompleted == false)
                {
                    Thread.Sleep(1000);
                }
            }
            return 0;
        }
    }
}