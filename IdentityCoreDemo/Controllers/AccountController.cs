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
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class AccountController : Controller
    {
        [AllowAnonymous]
        public IActionResult Login(string returnUrl)
        {
            if (User.Identity.Name != null && Request.Cookies["sso"] != null)//没有退出
            {
                Response.Cookies.Append("sso", $"{User.Identity.Name}_", new CookieOptions { Domain = "localhost" });//加密生成token，这里用“_”代表加密过
                //return Redirect(returnUrl ?? "/Home/About");
                return Redirect($"http://localhost:{returnUrl.Replace("_", "/")}");
            }
            ViewBag.ReturnUrl = $"http://localhost:{returnUrl.Replace("_", "/")}";
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel vm)
        {
            var path = Request.Path;
            if (User.Identity.Name != null && Request.Cookies["sso"] != null)
            {
                //认证成功，生成Token,直接登录
                //Response.Cookies.Append("sso", $"{User.Identity.Name}_", new CookieOptions { Domain = "localhost" });//加密生成token，这里用“_”代表加密过

                return Redirect(vm.ReturnUrl ?? "/Home/About");
            }

            var userStore = new UserStore();// context.RequestServices.GetService<UserStore>();
            var user = userStore.FindUser(vm.UserName, vm.Password);
            if (user == null)
            {
                await Response.WriteHtmlAsync(async res =>
                {
                    await res.WriteAsync($"<h1>用户名或密码错误。</h1>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/\">返回</a>");
                });
            }

            var claim = new ClaimsIdentity("Cookie");
            //claim.AddClaim(new Claim(ClaimTypes.Name,vm.UserName));
            claim.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            claim.AddClaim(new Claim(ClaimTypes.Name, user.Name));
            claim.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            claim.AddClaim(new Claim(ClaimTypes.MobilePhone, user.PhoneNumber));
            claim.AddClaim(new Claim(ClaimTypes.DateOfBirth, user.Birthday.ToString()));
            claim.AddClaim(new Claim(ClaimTypes.Role, user.Role.ToString()));

            var principal = new ClaimsPrincipal(claim);
            await HttpContext.SignInAsync(principal);
            Response.Cookies.Append("sso", $"{user.Name}_", new CookieOptions { Domain = "localhost" });//加密生成token，这里用“_”代表加密过

            return Redirect(vm.ReturnUrl ?? "/");
        }

        //获取Token(登录)
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> GetToken(LoginViewModel vm)
        {
            var userStore = new UserStore();
            var user = userStore.FindUser(vm.UserName, vm.Password);
            if (user == null)
            {
                await Response.WriteHtmlAsync(async res =>
                {
                    await res.WriteAsync($"<h1>用户名或密码错误。</h1>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/\">返回</a>");
                });
                return BadRequest();
            }

            var claim = new Claim[]{
                    new Claim(ClaimTypes.Name,user.Name),
                    new Claim(ClaimTypes.Role,user.Role),
                    new Claim(ClaimTypes.MobilePhone,user.PhoneNumber),
                    new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                    new Claim(ClaimTypes.DateOfBirth, user.Birthday.ToString()),
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


        [AllowAnonymous]
        public async Task Page(string returnUrl)
        {
            await Response.WriteHtmlAsync(async res =>
            {
                await res.WriteAsync($"<h1>用户名或密码错误。</h1>");
                await res.WriteAsync("<a class=\"btn btn-default\" href=\"/Account/Login\">返回</a>");
            });
        }
    }



    public class LoginViewModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
    }
}