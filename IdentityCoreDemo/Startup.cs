using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace IdentityCoreDemo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            #region 程序数据安全配置
            //services.AddDataProtection()
            // .SetApplicationName("SharedCookieApp");

            //services.ConfigureApplicationCookie(options => {
            //    options.Cookie.Name = ".AspNet.SharedCookie";
            //});
            #endregion

            #region Cookie用户认证配置
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;//Cookies
                })
                .AddCookie(options =>
                {
                    options.Cookie.Domain = "localhost";
                    options.Cookie.Name = "Cookies_authentication_sso";
                    options.Cookie.Path = "/";//限定cookie的作用域
                    options.AccessDeniedPath = "/Account/Page";
                    options.LoginPath = "/Account/Login";//指定验证失败后的默认跳转路径
                });

            #endregion

            #region JwtToken用户认证

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;                
            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    //ValidateIssuerSigningKey = true,
                    // 将下面两个参数设置为false，可以不验证Issuer和Audience，但是不建议这样做。
                    ValidateIssuer = false, // 默认为true
                    ValidateAudience = false, // 默认为true                                                  
                    ValidIssuer = "http://localhost",//Token颁发机构                        
                    ValidAudience = "http://localhost",//颁发给谁
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Hello-key-----wyt")),//密钥                    
                    //ClockSkew = TimeSpan.Zero,//允许的服务器时间偏移量
                };
            });

            #endregion

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
