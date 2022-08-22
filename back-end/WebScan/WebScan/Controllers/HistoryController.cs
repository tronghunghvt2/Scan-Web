using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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
                    idType = 2
                }).ToList();
                var listNmapScan = _context.NmapScans.Select(nm => new History
                {
                    value = nm.ipAddress,
                    typeScan = "Nmap Scan",
                    idScan = nm.idNmapScan,
                    idType = 1
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
        public IActionResult GetById(long idScan, long idType)
        {
            try
            {

                if(idType == 1)
                {
                    //var HistoryNmap = new HistoryNmap;
                    var nmap = _context.NmapScans.SingleOrDefault(ns => ns.idNmapScan == idScan);
                    return Ok(nmap);
                }
                else if(idType == 2)
                {
                    var sqlmap = _context.SqlmapScans.SingleOrDefault(sm => sm.idSqlmapScan == idScan);
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
