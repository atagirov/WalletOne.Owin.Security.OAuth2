using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WalletOne.Owin.Security.OAuth2.Provider;

namespace WalletOne.Owin.Security.OAuth2
{
    public class WalletOneAuthenticationOptions : AuthenticationOptions
    {
        public WalletOneAuthenticationOptions() 
            : base("WalletOne")
        {
            CallbackPath = new PathString("/signin-walletone");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "GetProfile.Type(All)"
            };

        }

        /// <summary>
        /// Gets or sets the Wallet One Oauth2 Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IWalletOneAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IWalletOneAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-walletone".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }
    }
}
