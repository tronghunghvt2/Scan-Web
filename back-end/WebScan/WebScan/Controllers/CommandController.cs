using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using WebScan.Data;

namespace WebScan.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommandController : ControllerBase
    {
        private readonly MyDbContext _context;
        public Queue<Models.CommandScan> Myqueue = new Queue<Models.CommandScan>();

        public CommandController(MyDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            try
            {
                var dsCommand = _context.Commands.ToList();
                if(dsCommand == null)
                {
                    return NotFound();
                }
                else
                {
                    return Ok(dsCommand);
                }
                
            }catch
            {
                return BadRequest();
            }
        }

        [HttpGet("{idTypeScan}")]
        public IActionResult GetById(int idTypeScan)
        {
            try
            {
                var dsCommand = _context.Commands.Where(cm => cm.idType == idTypeScan);
                if (dsCommand != null)
                {
                    return Ok(dsCommand);
                }
                else
                {
                    return NotFound();
                }
            } 
            catch
            {
                return BadRequest();
            }
        }

        [HttpPost]
        public IActionResult PostCommand(Models.CommandScan commandscan) 
        {
            try
            {
                if (commandscan.idType == 1)
                {
                    var nmapScan = new NmapScan { 
                        
                    };
                    commandscan.idScan = Guid.NewGuid();
                    nmapScan.idNmapScan = commandscan.idScan;
                    nmapScan.ipAddress = commandscan.value;
                    nmapScan.idCommand = commandscan.idCommand;
                    _context.NmapScans.Add(nmapScan);
                    _context.SaveChanges();
                    Myqueue.Enqueue(commandscan);
                    Controlbot();
                    return Ok(new
                    {
                        Sucess = true,
                        Data = nmapScan
                    });
                    
                }
                else if (commandscan.idType == 2)
                {
                    var sqlmapScan = new SqlmapScan();
                    commandscan.idScan = Guid.NewGuid();
                    sqlmapScan.idSqlmapScan = commandscan.idScan;
                    sqlmapScan.value = commandscan.value;
                    sqlmapScan.idCommand = commandscan.idCommand;
                    _context.SqlmapScans.Add(sqlmapScan);
                    _context.SaveChanges();
                    Myqueue.Enqueue(commandscan);
                    Controlbot();
                    return Ok(new
                    {
                        Sucess = true,
                        Data = sqlmapScan
                    });
                }
            }
            catch
            {
                return BadRequest();
            }
            return Ok();
        }
        private void Controlbot()
        {
            if (Myqueue.Count != 0)
            {
                Models.CommandScan commandscan = Myqueue.Dequeue();
                CallApiBot(commandscan);
            }
        }

        private async Task CallApiBot(Models.CommandScan commandScan)
        {
            string urlApiNmapBot = "http://192.168.56.128:8085/Scan/1,";
            string urlApiSqlmapBot = "http://192.168.56.128:8085/Scan/2,";

            if (commandScan.idType == 1)
            {

                // ket noi api bot nmap
                Guid id = commandScan.idScan;
                string path = urlApiNmapBot + id.ToString();
                HttpClient client = new HttpClient();
                HttpResponseMessage response = await client.GetAsync(path);
            }
            else if (commandScan.idType == 2)
            {
                // ket noi api bot sqlmap
                Guid id = commandScan.idScan;
                string path = urlApiSqlmapBot + id.ToString();
                HttpClient client = new HttpClient();
                HttpResponseMessage response = await client.GetAsync(path);
            }

        }

    }
}
