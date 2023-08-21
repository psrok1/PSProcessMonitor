using System.Management.Automation;

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
