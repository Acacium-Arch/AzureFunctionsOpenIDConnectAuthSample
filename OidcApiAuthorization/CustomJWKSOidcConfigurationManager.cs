using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OidcApiAuthorization.Abstractions;
using OidcApiAuthorization.Models;
using System.Security.Cryptography;

namespace OidcApiAuthorization
{
    public class CustomJWKSOidcConfigurationManager : IOidcConfigurationManager
    {
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

        private string validationPath;
        /// <summary>
        /// Construct a ConfigurationManager instance for retreiving and caching OpenIdConnectConfiguration
        /// from an Open ID Connect provider (issuer)
        /// </summary>
        public CustomJWKSOidcConfigurationManager(
            IOptions<OidcApiAuthorizationSettings> settingsOptions)
        {
            string issuerUrl = settingsOptions.Value.IssuerUrl;
            validationPath = settingsOptions.Value.ValidationPath;

            var documentRetriever = new HttpDocumentRetriever
            {
                RequireHttps = issuerUrl.StartsWith("https://")
            };

            // Setup the ConfigurationManager to call the issuer (i.e. Auth0) of the signing keys.
            // The ConfigurationManager caches the configuration it receives from the OpenID Connect
            // provider (issuer) in order to reduce the number or requests to that provider.
            //
            // The configuration is not retrieved from the OpenID Connect provider until the first time
            // the ConfigurationManager.GetConfigurationAsync() is called below.
            // e.g. $"{issuerUrl}.well-known/openid-configuration"
            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{issuerUrl}{validationPath}",
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever
            );
        }

        /// <summary>
        /// Returns the cached signing keys if they were retrieved previously.
        /// If they haven't been retrieved, or the cached keys are stale, then a fresh set of
        /// signing keys are retrieved from the OpenID Connect provider (issuer) cached and returned.
        /// This method will throw if the configuration cannot be retrieved, instead of returning null.
        /// </summary>
        /// <returns>
        /// The current set of the Open ID Connect issuer's signing keys.
        /// </returns>
        public async Task<IEnumerable<SecurityKey>> GetIssuerSigningKeysAsync()
        {
            // This is where we will have the dilemma - .well-known/openid-configuration
            // vs custom jwks endpoint.
            // This configuration is reliant on analysing the validationPath for 'jwks'.
            OpenIdConnectConfiguration configuration = await _configurationManager.GetConfigurationAsync(
                CancellationToken.None);


            if ((validationPath.ToLower()).Contains("jwks"))
            {
                // we need to do some work here to extract the keys from the jwks endpoint and
                // place into a SecurityKey array
                var keys = new List<SecurityKey>();
                var json = Newtonsoft.Json.JsonConvert.DeserializeObject<List<JwksKey>>(configuration.AdditionalData["keys"].ToString());
                foreach (var k in json)
                {
                    var e = Base64UrlEncoder.DecodeBytes(k.e);
                    var n = Base64UrlEncoder.DecodeBytes(k.n);
                    var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n })
                    {
                        KeyId = k.kid
                    };

                    keys.Add(key);
                }

                return keys;
            }
            else
            {
                // assume .well-known/openid-configuration standard endpoint for OpenId
                return configuration.SigningKeys;
            }
        }

        /// <summary>
        /// Requests that the next call to GetIssuerSigningKeysAsync() obtain new signing keys.
        /// If the last refresh was greater than RefreshInterval then the next call to
        /// GetIssuerSigningKeysAsync() will retrieve new configuration (signing keys).
        /// If RefreshInterval == System.TimeSpan.MaxValue then this method does nothing.
        /// </summary>
        /// <remarks>
        /// RefreshInterval defaults to 30 seconds (00:00:30).
        /// </remarks>
        public void RequestRefresh()
        {
            _configurationManager.RequestRefresh();
        }
    }
}
