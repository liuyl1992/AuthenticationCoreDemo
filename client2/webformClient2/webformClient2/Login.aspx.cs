using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace webformClient2
{
    public partial class Login : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }
        protected void Login_Click(object sender, EventArgs e)
        {
            if (UserName.Text == "bob" && UserPass.Text == "bob")
            {
                var claim = new ClaimsIdentity("Cookie");
                claim.AddClaim(new Claim(ClaimTypes.Name, UserName.Text));

                var principal = new ClaimsPrincipal(claim);

                FormsAuthentication.SetAuthCookie(UserName.Text, false);
                Response.Redirect(Request.QueryString["ReturnUrl"] ?? "/");
            }
            if (User.Identity.IsAuthenticated)
            {
                FormsAuthentication.SetAuthCookie(UserName.Text, false);
                Response.Redirect(Request.QueryString["ReturnUrl"] ?? "/");
            }

            else
            {
                Msg.Text = "Invalid credentials. Please try again.";
            }
        }
    }
}