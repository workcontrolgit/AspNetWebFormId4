using System;
using System.Linq;
using System.Security.Claims;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace AspNetWebFormImplicitFlow
{
    public partial class About : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            ClaimsPrincipal cp = Page.User as ClaimsPrincipal;
            var claims = cp.Claims.ToList();
        }
    }
}