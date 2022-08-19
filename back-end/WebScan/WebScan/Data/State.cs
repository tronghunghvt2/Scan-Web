using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("state")]
    public class State
    {
        [Key]
        public long idState { get; set; }
        public string value { get; set; }

        public virtual ICollection<Port> Ports { get; set; }
    }
}
