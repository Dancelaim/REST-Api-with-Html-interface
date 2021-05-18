using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.HttpSys;
using Microsoft.IdentityModel.Tokens;

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

using WebApI.Model;
using WebApI.Security;

namespace WebApI.Controllers
{
    public class AccountController : Controller
    {
        Context db;
        public AccountController(Context context)
        {
            db = context;
        }

        [HttpPost("/token")]
        public IActionResult Token()
        {

                string authHeader = HttpContext.Request.Headers["Authorization"];
                if (authHeader != null)
                {
                    var authHeaderValue = AuthenticationHeaderValue.Parse(authHeader);
                    if (authHeaderValue.Scheme.Equals(AuthenticationSchemes.Basic.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        var credentials = Encoding.UTF8
                                            .GetString(Convert.FromBase64String(authHeaderValue.Parameter ?? string.Empty))
                                            .Split(':', 2);
                        if (credentials.Length == 2)
                        {
                            var identity = GetIdentity(credentials[0], credentials[1]);
                            if (identity == null)
                            {
                                return Unauthorized(new { errorText = "Invalid username or password." });
                            }
                            var now = DateTime.UtcNow;
                            var jwt = new JwtSecurityToken(issuer: AuthOptions.ISSUER, audience: AuthOptions.AUDIENCE, notBefore: now, claims: identity.Claims,
                                    expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                            var response = new
                            {
                                access_token = encodedJwt,
                                username = identity.Name
                            };
                            return Json(response);
                        }
                    }
                }
            return Unauthorized();


        }

        private ClaimsIdentity GetIdentity(string username, string password)
        {
            User User = db.Users.FirstOrDefault(x => x.Login == username && x.Password == password);
            if (User != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, User.Login),
                    new Claim(ClaimsIdentity.DefaultRoleClaimType, User.Role)
                };
                ClaimsIdentity claimsIdentity =  new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }

            // если пользователя не найдено
            return null;
        }
    }
}
