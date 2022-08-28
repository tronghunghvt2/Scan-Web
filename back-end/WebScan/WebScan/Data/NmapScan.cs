using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("nmapScan")]
    public class NmapScan
    {
        [Key]
        public Guid idNmapScan { get; set; }
        [Required]
        public string ipAddress { get; set; }
        public string timeStart { get; set; }
        public string location { get; set; }
        public string coordinates { get; set; }

        public virtual ICollection<Port> Ports { get; set; }
        public long? idCommand { get; set; }
        [ForeignKey("idCommand")]
        public Command Command { get; set; }
    }
}
