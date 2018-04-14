using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using CookieSample;
using CookieSample.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace IdentityCoreDemo.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    public class APITokenController : Controller
    {
        //获取Token(登录)
        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<IActionResult> GetToken(LoginViewModel vm)
        {
            var userStore = new UserStore();
            var user = userStore.FindUser(vm.UserName, vm.Password);
            if (user == null)
            {
                return BadRequest(new { error = "没有此用户" });
            }

            var claim = new Claim[]{
                    new Claim(ClaimTypes.Name,user.Name),
                    new Claim(ClaimTypes.Role,user.Role),
                    new Claim(ClaimTypes.MobilePhone,user.PhoneNumber),
                    new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.DateOfBirth, user.Birthday.ToString()),
                    new Claim("company", "中国公司"),
            };

            //取出密钥
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Hello-key-----wyt"));
            //签名加密
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //生成token
            var token = new JwtSecurityToken(
                issuer: "http://localhost",
                audience: "http://localhost",
                claims: claim,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            //可拿生成的token去 https://jwt.io/ 网站验证
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });

        }

        /// <summary>
        /// 移除Token（退出）请求头中Authorization属性中存放之前发放的Token,以bearer 开头
        /// </summary>
        /// <param name="vm"></param>
        /// <returns></returns>
        [HttpPost("removeToken")]
        public async Task<IActionResult> RemoveToken()
        {
            var authResult = await HttpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
            var user = User.Identity.Name;
            var dateOfBirth = User.Claims.Where(s => s.Type == ClaimTypes.DateOfBirth).FirstOrDefault()?.Value;
            if (authResult.Succeeded && authResult.Principal.Identity.IsAuthenticated)
            {
                await HttpContext.SignOutAsync(JwtBearerDefaults.AuthenticationScheme);
                return Ok($"{user}退出成功");
            }
            return BadRequest("认证失败");

        }
    }
}
