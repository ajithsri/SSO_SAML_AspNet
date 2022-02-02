using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using ITfoxtec.Identity.Saml2.Util;
using System.IdentityModel.Claims;
using System.Web.Helpers;
using System.Web;

namespace SSO_SAML_AspNet.Helper
{
    public class IdentityConfigHelper
    {
        public  Saml2Configuration GetSAMLConfig1()
        {
            var config = new Saml2Configuration();
            config.Issuer = ConfigurationManager.AppSettings["Saml2:Issuer"];
            config.AllowedAudienceUris.Add(config.Issuer);

            config.CertificateValidationMode = X509CertificateValidationMode.ChainTrust;
            config.RevocationMode = X509RevocationMode.NoCheck;

            var entityDescriptor = new EntityDescriptor();
            //entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri("https://dev-30220723.okta.com/app/exk3qrnqbrhJVPLOE5d7/sso/saml/metadata"));
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(ConfigurationManager.AppSettings["Saml2:IdPMetadata"]));
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                config.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                config.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
            }
            else
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }

            return config;
        }

        public Saml2Configuration GetSAMLConfig()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

            var config = new Saml2Configuration
            {
                Issuer = ConfigurationManager.AppSettings["Saml2:Issuer"]
            };
            config.AllowedAudienceUris.Add(config.Issuer);

            // additional settting if you want to use certificated to validate the response.
            //config.SignatureAlgorithm = ConfigurationManager.AppSettings["Saml2:SignatureAlgorithm"];
            //config.SigningCertificate = CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml2:SigningCertificateFile"]), ConfigurationManager.AppSettings["Saml2:SigningCertificatePassword"]);

            config.CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), ConfigurationManager.AppSettings["Saml2:CertificateValidationMode"]);
            config.RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), ConfigurationManager.AppSettings["Saml2:RevocationMode"]);


            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(ConfigurationManager.AppSettings["Saml2:IdPMetadata"]));
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                config.AllowedIssuer = entityDescriptor.EntityId;
                config.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                config.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                if (entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                {
                    config.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
                }
            }
            else
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }

            return config;
        }
    }
}