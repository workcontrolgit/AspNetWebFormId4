using Microsoft.Owin;

using Owin;

[assembly: OwinStartup(typeof(AspNetWebFormImplicitFlow.Startup))]

namespace AspNetWebFormImplicitFlow
{
    public partial class Startup
    {

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

    }
}