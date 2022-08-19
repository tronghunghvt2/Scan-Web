using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("port")]
    public class Port
    {
        [Key]
        public long idPort { get; set; }
        public string value { get; set; }


        public long idNmapScan { get; set; }
        [ForeignKey("idNmapScan")]
        public NmapScan NmapScan { get; set; }


        public long idState { get; set; }
        [ForeignKey("idState")]
        public State State { get; set; }


        public long idService { get; set; }
        [ForeignKey("idService")]
        public Service Service { get; set; }
    }
}
