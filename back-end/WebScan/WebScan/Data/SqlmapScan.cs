using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("sqlmapScan")]
    public class SqlmapScan
    {

        [Key]
        public Guid idSqlmapScan { get; set; }
        [Required]
        public string value { get; set; }
        public string message { get; set; }
        public string timeStart { get; set; }
        public string timeEnd { get; set; }
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; }
        public virtual ICollection<Database> Databases { get; set; }
        public long? idCommand { get; set; }
        [ForeignKey("idCommand")]
        public Command Command { get; set; }
    }
}
