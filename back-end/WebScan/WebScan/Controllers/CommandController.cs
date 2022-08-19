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
            var dsCommand = _context.Commands.ToList();
            return Ok(dsCommand);
        }

        [HttpGet("{idTypeScan}")]
        public IActionResult GetById(int idTypeScan)
        {
            var dsCommand = _context.Commands.Where(cm => cm.idType == idTypeScan);
            if(dsCommand != null)
            {
                return Ok(dsCommand);
            }
            else
            {
                return BadRequest();
            }
        }
    }
}
