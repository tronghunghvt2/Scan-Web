using System;
using System.ComponentModel.DataAnnotations;

namespace WebScan.Models
{
    public class Command
    {
        [Required]
        public long idType { get; set; }
        [Required]
        public long idCommand { get; set; }
        [Required]
        public string value { get; set; }
        
    }

    public class CommandScan : Command
    {
        public Guid idScan { get; set; }
    }
}
