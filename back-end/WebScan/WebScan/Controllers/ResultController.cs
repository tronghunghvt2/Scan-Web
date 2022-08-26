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
    public class ResultController : ControllerBase
 
    {
        private readonly MyDbContext _context;

        public ResultController(MyDbContext context)
        {
            _context = context;
        }
        [HttpGet]
        public IActionResult GetAll()
        {
            try
            {
                var dsResult1 = _context.SqlmapScans.ToList();
                if (dsResult1 == null )
                {
                    return NotFound();
                }
                else
                {
                    return Ok(dsResult1);
                }

            }
            catch
            {
                return BadRequest();
            }
        }

        [HttpGet("{idTypeScan}")]
        public IActionResult GetById (int idTypeScan)
        {
            try
            {
                var dsResult1 = _context.SqlmapScans.SingleOrDefault(Result => Result.idSqlmapScan == idTypeScan);
                if (dsResult1 != null)
                {
                    return Ok(dsResult1);
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

        [HttpDelete("{idTypeScan}")]
        public IActionResult Remove(int idTypeScan)
        {
            try
            {
                var dsResult1 = _context.SqlmapScans.SingleOrDefault(Result => Result.idSqlmapScan == idTypeScan);
                if (dsResult1 == null)
                {
                    return NotFound();
                }
                _context.SqlmapScans.Remove(dsResult1);

                return Ok();
            }
            catch
            {
                return BadRequest();
            }
        }
    }
}
