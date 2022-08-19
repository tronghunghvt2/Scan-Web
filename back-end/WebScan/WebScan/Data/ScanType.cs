using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("scanType")]
    public class ScanType
    {
        [Key]
        public long idType { get; set; }
        public string value { get; set; }

        public virtual ICollection<Command> Commands { get; set; }
    }
}
