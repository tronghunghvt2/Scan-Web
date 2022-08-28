using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("table")]
    public class Table
    {
        [Key]
        public Guid idTable { get; set; }
        public string value { get; set; }
        public virtual ICollection<Dump> Dumps { get; set; }
        public Guid? idDb { get; set; }
        [ForeignKey("idDb")]
        public Database Database { get; set; }
    }
}
