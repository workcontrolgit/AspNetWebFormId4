using System;
using System.Linq;
using System.Security.Claims;
using System.Web.UI;

namespace AspNetWebFormImplicitFlow
{
    public partial class About : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            //example code to get claims from code behind
            ClaimsPrincipal cp = Page.User as ClaimsPrincipal;
            //example code to extract access_token using Linq
            var accessTokenClaim = cp.Claims
            .Where(x => x.Type == "access_token")
            .FirstOrDefault();
            var accessToken = accessTokenClaim.Value;


            //example code to extract id_token using Linq
            var idTokenClaim = cp.Claims
            .Where(x => x.Type == "id_token")
            .FirstOrDefault();

            var idToken = idTokenClaim.Value;

        }
    }
}