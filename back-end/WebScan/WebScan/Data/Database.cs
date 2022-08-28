using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("database")]
    public class Database
    {
        [Key]
        public Guid idDb { get; set; }
        public string value { get; set; }
        public virtual ICollection<Table> Tables { get; set; }
        public Guid? idSqlmapScan { get; set; }
        [ForeignKey("idSqlmapScan")]
        public SqlmapScan SqlmapScan { get; set; }
    }
}
