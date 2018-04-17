using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace webformClient2
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                //认证通过
                if (User.Identity.IsAuthenticated)
                {
                    Welcome.Text = "Hello,这是Client2, " + Context.User.Identity.Name;
                }
                else
                {
                    //认证不为空(认证中心发放过)
                    if (!string.IsNullOrEmpty(Request.Cookies.Get("sso")?.Value))
                    {
                        //创建局部会话
                        //解密
                        var cookieValue = Request.Cookies.Get("sso").Value?.Replace("_", string.Empty);
                        FormsAuthentication.SetAuthCookie(cookieValue, false);
                        Response.Redirect("/");
                        return;
                    }
                    //转去sso认证中心
                    Response.Redirect("http://localhost:63925/Account/Login?ReturnUrl=57951_Default.aspx");
                }
            }
        }
        protected void Signout_Click(object sender, EventArgs e)
        {
            FormsAuthentication.SignOut();
            Response.Cookies.Remove("sso");
            Response.Redirect("welcome.aspx");
        }
    }
}