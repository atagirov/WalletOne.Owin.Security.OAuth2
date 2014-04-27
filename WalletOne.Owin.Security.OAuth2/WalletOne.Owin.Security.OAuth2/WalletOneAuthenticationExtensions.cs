using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WalletOne.Owin.Security.OAuth2
{
    public static class WalletOneAuthenticationExtensions
    {
        public static IAppBuilder UseGooglePlusAuthentication(this IAppBuilder app, WalletOneAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(WalletOneAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGooglePlusAuthentication(this IAppBuilder app, string clientId)
        {
            return app.UseGooglePlusAuthentication(new WalletOneAuthenticationOptions
            {
                ClientId = clientId
            });
        }
    }
}
