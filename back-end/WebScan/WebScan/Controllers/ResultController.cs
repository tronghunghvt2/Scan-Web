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
    public class ResultController : ControllerBase
 
    {
        private readonly MyDbContext _context;

        public ResultController(MyDbContext context)
        {
            _context = context;
        }

        [HttpGet("{idType},{idScan}")]
        public IActionResult GetById(long idType, Guid idScan)
        {
            try
            {
                if (idType == 1) {
                    var Result = _context.NmapScans.SingleOrDefault(rs => rs.idNmapScan == idScan);
                    if (Result != null)
                    {
                        return Ok(Result);
                    }
                    else
                    {
                        return NotFound();
                    }
                }
                else if(idType == 2)
                {
                    var Result = _context.SqlmapScans.SingleOrDefault(rs => rs.idSqlmapScan == idScan);
                    if(Result != null)
                    {
                        return Ok(Result);
                    }
                    else
                    {
                        return NotFound();
                    }
                }
                else
                {
                    return BadRequest();
                }
            }
            catch
            {
                return BadRequest();
            }
            
        }


    }
}
