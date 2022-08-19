using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("command")]
    public class Command
    {
        [Key]
        public long idCommand { get; set; }

        public string name { get; set; }

        public string value { get; set; }

        public virtual ICollection<SqlmapScan> SqlmapScans { get; set; }
        public virtual ICollection<NmapScan> NmapScans { get; set; }

        public long? idType { get; set; }
        [ForeignKey("idType")]
        public ScanType ScanType { get; set; }
    }
}
