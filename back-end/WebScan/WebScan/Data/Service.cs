using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("service")]
    public class Service
    {
        [Key]
        public long idService { get; set; }
        public string value { get; set; }
        public virtual ICollection<Port> Ports { get; set; }

    }
}
