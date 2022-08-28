using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using WebScan.Data;
using WebScan.Models;

namespace WebScan.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ScanController : ControllerBase
    {
        private readonly MyDbContext _context;

        public ScanController(MyDbContext context)
        {
            _context = context;
        }

        [HttpGet("{idType},{idScan}")]
        public IActionResult GetValue(long idType, Guid idScan)
        {
            try
            {
                if (idType == 1)
                {
                    // lấy dữ liệu cho bot nmap
                    var nmap = _context.NmapScans.SingleOrDefault(nm => nm.idNmapScan == idScan);
                    var scan = new Scan
                    {
                        idCommand = nmap.idCommand,
                        idScan = nmap.idNmapScan,
                        value = nmap.ipAddress,
                        idType = idType
                    };
                    return Ok(scan);
                }
                else if (idType == 2)
                {
                    // lấy dữ liệu cho bot sqlmap
                    var sqlmap = _context.SqlmapScans.SingleOrDefault(sm => sm.idSqlmapScan == idScan);
                    var scan = new Scan
                    {
                        idScan = sqlmap.idSqlmapScan,
                        idCommand = sqlmap.idCommand,
                        value = sqlmap.value,
                        idType = idType
                    };
                    return Ok(scan);
                }
            }
            catch
            {
                return BadRequest();
            }

            return Ok();
        }

        [HttpPost]
        public IActionResult GetResult(Models.ResultScan result)
        {

            if (result.idType == 2)
            {
                var sqlmapScan = _context.SqlmapScans.Find(result.idScan);
                sqlmapScan.message = result.message;
                sqlmapScan.timeStart = result.time_Start;
                sqlmapScan.timeEnd = result.time_End;

                var vuls = new Vulnerability();
                foreach (var vul in result.vuls)
                {
                    vuls.value = vul;
                    vuls.idSqlmapScan = result.idScan;
                    _context.Vulnerabilities.Add(vuls);
                    _context.SaveChanges();
                }

                var database = new Database();
                var idDB = Guid.NewGuid();
                database.idDb = idDB;
                database.value = result.database;
                database.idSqlmapScan = result.idScan;
                _context.Databases.Add(database);
                _context.SaveChanges();

                var tables = new Table();
                var idTable = Guid.NewGuid();
                foreach (var table in result.table)
                {
                    
                    tables.idTable = idTable;
                    tables.value = table;
                    tables.idDb = idDB;
                    _context.Tables.Add(tables);
                    _context.SaveChanges();
                }

                var dump = new Dump();
                dump.value = result.dump;
                dump.idTable = idTable;
                _context.Dumps.Add(dump);
                _context.SaveChanges();
                return Ok();
            }
            else if (result.idType == 1)
            {
                var nmap = _context.NmapScans.SingleOrDefault(nm => nm.idNmapScan == result.idScan);
                nmap.timeStart = result.time_Start;
                nmap.location = result.location;
                nmap.coordinates = result.coordinates;

                var port = new Port();
                var state = new State();
                var service = new Service();
                int r = result.port.Length;
                for (int i = 0; i < r; i++)
                {
                    var idPort =  Guid.NewGuid();
                    port.idPort = idPort;
                    port.value = result.port[i];
             
                    if (result.state[i] == "open")
                    {
                        port.idState = 1;
                    }
                    else
                    {
                        port.idState = 2;
                    }

                    if (result.service[i] == "http")
                    {
                        port.idService = 1;
                    }
                    else if (result.service[i] == "https")
                    {
                        port.idService = 2;
                    }
                    else if (result.service[i] == "https-proxy")
                    {
                        port.idService = 3;
                    }
                    _context.Ports.Add(port);
                    _context.SaveChanges();

                }
                return Ok();
            }
            return Ok();
        }
    }
}
