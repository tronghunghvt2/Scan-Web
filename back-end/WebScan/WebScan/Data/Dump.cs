using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebScan.Data
{
    [Table("dump")]
    public class Dump
    {
        [Key]
        public long idDump { get; set; }
        public string value { get; set; }
        public Guid? idTable { get; set; }
        [ForeignKey("idTable")]
        public Table Table { get; set; }
    }
}
