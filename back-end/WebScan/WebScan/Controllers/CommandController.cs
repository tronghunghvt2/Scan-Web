using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using WebScan.Data;

namespace WebScan.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommandController : ControllerBase
    {
        private readonly MyDbContext _context;

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
        public IActionResult PostCommand(Models.Command command) 
        {
            try
            {
                if (command.idType == 1)
                {
                    var nmapScan = new NmapScan();
                    nmapScan.ipAddress = command.value;
                    return Ok(new
                    {
                        Sucess = true,
                        Data = nmapScan
                    });
                }
                else if (command.idType == 2)
                {
                    var sqlmapScan = new SqlmapScan();
                    sqlmapScan.value = command.value;
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
    }
}
