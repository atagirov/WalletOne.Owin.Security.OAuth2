using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WalletOne.Owin.Security.OAuth2
{
    public class WalletOneAuthenticationOptions : AuthenticationOptions
    {
        public WalletOneAuthenticationOptions() 
            : base("WalletOne")
        {
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
    }
}
