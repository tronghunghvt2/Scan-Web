using System;

namespace WebScan.Models
{
    public class Scan
    {
        public Guid idScan { get; set; }
        public long? idCommand { get; set; }
        public string value { get; set; }
        public long idType { get; set; }

    }

    public class ResultScan : Scan
    {
        public string message { get; set; }
        public string time_Start { get; set; }
        public string time_End { get; set; }
        public string[] vuls { get; set; }
        public string database { get; set; }
        public string[] table { get; set; }
        public string dump { get; set; }


        // result nmap


        public string location { get; set; }
        public string coordinates { get; set; }
        public string[] port { get; set; }
        public string[] state { get; set; }
        public string[] service { get; set; }
    }

}
