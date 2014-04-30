using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace WalletOne.Owin.Security.OAuth2.Provider
{
    public class WalletOneAuthenticatedContext: BaseContext
    {
        public WalletOneAuthenticatedContext(IOwinContext context, JObject profile, string accessToken)
            : base(context)
        {
            Profile = profile;
            AccessToken = accessToken;

            Id = (string)profile["UserId"];

            JArray userAttributes = profile["UserAttributes"] as JArray;

            if (userAttributes != null)
            {
                foreach (JToken token in userAttributes.Children())
                {
                    switch ((string)token["UserAttributeTypeId"])
                    {
                        case "NtfEmail":
                            Email = (string)token["DisplayValue"];
                            break;
                        case "Email":
                            if (string.IsNullOrEmpty(Email) && (string)token["VerificationState"] == "Verified")
                                Email = (string)token["DisplayValue"];
                            break;
                        case "Title":
                            Name = (string)token["DisplayValue"];
                            break;
                        default:
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Gets the JSON-serialized profile
        /// </summary>
        /// <remarks>
        /// Contains the WalletOne profile obtained from the endpoint https://app.w1.ru/OpenApi/profile.  For more information
        /// see https://docs.google.com/document/pub?id=1taj9jpnfGl6yMFXJkDaAzt8aP8gCeUYaTDG3k3BSmlk&embedded=true#kix.wd1ei2bp5ks1
        /// </remarks>
        public JObject Profile { get; private set; }

        /// <summary>
        /// Gets the WalletOne OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the WalletOne UserID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the email address for the account
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
