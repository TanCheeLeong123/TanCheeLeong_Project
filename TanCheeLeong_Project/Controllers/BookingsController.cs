using TanCheeLeong_Project.Data;
using TanCheeLeong_Project.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace TanCheeLeong_Project.Controllers
{
    [Authorize]
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class BookingsController : ControllerBase
    {

        private readonly ApplicationDbContext _context;

        public BookingsController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Roles = MemberRoles.Admin)]
        // GET: api/Bookings
        [HttpGet]
        public IActionResult GetAll()
        {
            return Ok(_context.Bookings);
        }
    }
}
