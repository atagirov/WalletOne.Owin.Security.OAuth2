using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Globalization;
using System.Net.Http;
using WalletOne.Owin.Security.OAuth2.Provider;

namespace WalletOne.Owin.Security.OAuth2
{
    public class WalletOneAuthenticationMiddleware : AuthenticationMiddleware<WalletOneAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public WalletOneAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WalletOneAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", "ClientId"));

            logger = app.CreateLogger<WalletOneAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new WalletOneAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(typeof(WalletOneAuthenticationMiddleware).FullName, Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            httpClient = new HttpClient();
            //httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            //{
            //    Timeout = Options.BackchannelTimeout,
            //    MaxResponseContentBufferSize = 1024 * 1024 * 10
            //};
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:WalletOne.Owin.Security.OAuth2.WalletOneAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<WalletOneAuthenticationOptions> CreateHandler()
        {
            return new WalletOneAuthenticationHandler(httpClient, logger);
        }

        //private HttpMessageHandler ResolveHttpMessageHandler(WalletOneAuthenticationOptions options)
        //{
        //    HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

        //    // If they provided a validator, apply it or fail.
        //    if (options.BackchannelCertificateValidator != null)
        //    {
        //        // Set the cert validate callback
        //        var webRequestHandler = handler as WebRequestHandler;
        //        if (webRequestHandler == null)
        //        {
        //            throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
        //        }
        //        webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
        //    }

        //    return handler;
        //}
    }
}
