using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace PSProcessMonitor
{
    [Cmdlet(VerbsCommunications.Read, "PML")]
    public class ReadPML : Cmdlet
    {
        [Parameter(Position = 0)]
        public string FileName
        {
            get { return fileName; }
            set { fileName = value; }
        }
        private string fileName;

        protected override void ProcessRecord()
        {
            using (PMLReader reader = PMLReader.OpenFile(FileName))
            {
                foreach (DetailedEvent ev in reader.GetEvents())
                {
                    WriteObject(ev);
                }
            }
        }
    }
}
