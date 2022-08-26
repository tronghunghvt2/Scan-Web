using WebScan.Data;

namespace WebScan.Models
{
    public class History
    {
        public string value { get; set; }
        public string typeScan { get; set; }
        public long? idScan { get; set; }
        public long? idType { get; set; }
    }

    public class HistoryNmap : History
    {
        
        public string timeStart { get; set; }
        public string location  { get; set; }
        public string coordinates { get; set; }
        public Port port { get; set; }
        
    }

    public class HistorySql : History 
    { 
        
        public string timeStart { get; set; }
        public string timeEnd { get; set; }
        public Vulnerability vulnerability { get; set; }
        public Database database { get; set; }
        public Table table { get; set; }
    }

}
