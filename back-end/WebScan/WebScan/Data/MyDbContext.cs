using Microsoft.EntityFrameworkCore;

namespace WebScan.Data
{
    public class MyDbContext: DbContext
    {
        public MyDbContext(DbContextOptions option): base(option) { }

        #region
        public DbSet<Command> Commands { get; set; }
        public DbSet<ScanType> ScanTypes { get; set; }
        public DbSet<SqlmapScan> SqlmapScans { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
        public DbSet<Database> Databases { get; set; }
        public DbSet<Table> Tables { get; set; }
        public DbSet<Dump> Dumps { get; set; }

        #endregion

    }
}
