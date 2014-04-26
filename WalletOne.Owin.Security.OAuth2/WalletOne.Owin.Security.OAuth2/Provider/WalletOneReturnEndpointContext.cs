using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WalletOne.Owin.Security.OAuth2.Provider
{
    public class WalletOneReturnEndpointContext: ReturnEndpointContext
    {
        public WalletOneReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        { }
    }
}
