using WebScan.Data;

namespace WebScan.Models
{
    public class Result
    {
    }

    public class ResultNmap : Result
    {
        public string timeStart { get; set; }
        public string location { get; set; }
        public string coordinates { get; set; }
        public Port port { get; set; }
    }

    public class ResultSqlmap : Result
    {
        public string timeStart { get; set; }
        public string timeEnd { get; set; }
        public Vulnerability vulnerability { get; set; }
        public Database database { get; set; }
        public Table table { get; set; }
    }
}
