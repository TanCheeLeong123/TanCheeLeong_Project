using TanCheeLeong_Project.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TanCheeLeong_Project.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _memberManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticateController(
            UserManager<IdentityUser> memberManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _memberManager = memberManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var member = await _memberManager.FindByNameAsync(model.Username);
            if (member != null && await _memberManager.CheckPasswordAsync(member, model.Password))
            { 
                var memberRoles = await _memberManager.GetRolesAsync(member);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, member.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var memberRole in memberRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, memberRole));
                }

                var token = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var memberExists = await _memberManager.FindByNameAsync(model.Username);
            if (memberExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Member already exists!" });

            IdentityUser member = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _memberManager.CreateAsync(member, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Member creation failed! Please check member details and try again." });

            if (!await _roleManager.RoleExistsAsync(MemberRoles.Member))
                await _roleManager.CreateAsync(new IdentityRole(MemberRoles.Member));
            if (await _roleManager.RoleExistsAsync(MemberRoles.Member))
            {
                await _memberManager.AddToRoleAsync(member, MemberRoles.Member);
            }
            return Ok(new Response { Status = "Success", Message = "Member created successfully!" });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var memberExists = await _memberManager.FindByNameAsync(model.Username);
            if (memberExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Member already exists!" });

            IdentityUser member = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _memberManager.CreateAsync(member, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Member creation failed! Please check member details and try again." });

            if (!await _roleManager.RoleExistsAsync(MemberRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(MemberRoles.Admin));
            if (await _roleManager.RoleExistsAsync(MemberRoles.Admin))
            {
                await _memberManager.AddToRoleAsync(member, MemberRoles.Admin);
            }
            return Ok(new Response { Status = "Success", Message = "Member created successfully!" });
        }
    }
}
