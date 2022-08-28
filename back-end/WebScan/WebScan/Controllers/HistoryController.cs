using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using WebScan.Data;
using WebScan.Models;

namespace WebScan.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HistoryController : ControllerBase
    {
        private readonly MyDbContext _context;

        public  HistoryController(MyDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult GetAll(int pageIndex = 1)
        {
            try
            {
                var listSqlmapScan = _context.SqlmapScans.Select(sm => new History
                {
                    value = sm.value,
                    typeScan = "Sql Scan",
                    idScan = sm.idSqlmapScan,
                    idType = 2,
                    idCommand = sm.idCommand
                }).ToList();
                var listNmapScan = _context.NmapScans.Select(nm => new History
                {
                    value = nm.ipAddress,
                    typeScan = "Nmap Scan",
                    idScan = nm.idNmapScan,
                    idType = 1,
                    idCommand = nm.idCommand
                }).ToList();

                var unionList = listSqlmapScan.Union(listNmapScan).Skip((pageIndex-1)*10).Take(10).ToList();
                
                if (unionList.Count == 0)
                {
                    return NotFound();
                }
                else
                {
                    return Ok(unionList);
                }
                
            } catch
            {
                return BadRequest();
            }
        }

        [HttpGet("{idScan},{idType}")]
        public IActionResult GetById(Guid idScan, long idType)
        {
            try
            {

                if(idType == 1)
                {
                    //var HistoryNmap = new HistoryNmap;
                    var listnmap = _context.NmapScans.ToList();
                    var listPort = _context.Ports.ToList();
                    var listState = _context.states.ToList();
                    var listService = _context.services.ToList();

                    var list = from a in listnmap
                               join b in listPort on a.idNmapScan equals b.idNmapScan
                               join c in listState on b.idState equals c.idState
                               join d in listService on b.idService equals d.idService
                               select new HistoryNmap
                               {
                                   idScan = a.idNmapScan,
                                   typeScan = "Nmap Scan",
                                   value = a.ipAddress,
                                   timeStart = a.timeStart,
                                   location = a.location,
                                   coordinates = a.coordinates,
                                   port = (Port)a.Ports,
                                   state = (State)b.State,
                                   service = (Service)b.Service
                               };
                    var list_s = list.ToList();
                    var nmap = list_s.SingleOrDefault(sm => sm.idScan == idScan);
                    if (nmap == null)
                    {
                        NotFound();
                    }
                    return Ok(nmap);
                }
                else if(idType == 2)
                {
                    var listVul = _context.Vulnerabilities.ToList();
                    var listSqlmap = _context.SqlmapScans.ToList();

                    var listDb = _context.Databases.ToList();
                    var listTable = _context.Tables.ToList();
                    var listDump = _context.Dumps.ToList();

                    var list = from a in listSqlmap
                               join b in listVul on a.idSqlmapScan equals b.idSqlmapScan
                               join c in listDb on a.idSqlmapScan equals c.idSqlmapScan
                               join d in listTable on c.idDb equals d.idDb
                               join e in listDump on d.idTable equals e.idTable
                               select new HistorySqlmap
                               {
                                   idScan = a.idSqlmapScan,
                                   typeScan = "Sqlmap Scan",
                                   value = a.value,
                                   message = a.message,
                                   timeStart = a.timeStart,
                                   timeEnd = a.timeEnd,
                                   vulnerability = (Vulnerability)a.Vulnerabilities,
                                   database = (Database)a.Databases,
                                   table = (Table)c.Tables,
                                   dump = (Dump)d.Dumps
                               };
                    var list_s = list.ToList();
                    var sqlmap = list_s.SingleOrDefault(sm => sm.idScan == idScan);
                    return Ok(sqlmap);
                }
                else
                {
                    return NotFound();
                }
            } catch
            {
                return BadRequest();
            }
        }
    }
}
