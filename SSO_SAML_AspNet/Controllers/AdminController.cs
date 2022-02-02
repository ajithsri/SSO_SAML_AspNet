using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Mvc;
using ITfoxtec.Identity.Saml2.Schemas;
using SSO_SAML_AspNet.Helper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace SSO_SAML_AspNet.Controllers
{
    public class AdminController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        const string assertionConsumerServiceUrl = "https://localhost:44370/admin/LoginAssertionConsumerService";

        public ActionResult Index(string name)
        {
            return View("Index", null, name);
        }

        [HttpGet]
        public ActionResult Login(string returnUrl = null)
        {
            var config = (new IdentityConfigHelper()).GetSAMLConfig();

            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)
            {
                AssertionConsumerServiceUrl = new System.Uri(assertionConsumerServiceUrl)
            }).ToActionResult();
        }

        [HttpPost]
        public ActionResult LoginAssertionConsumerService()
        {
            var config = (new IdentityConfigHelper()).GetSAMLConfig();

            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);

            //saml2AuthnResponse.CreateSession(claimsAuthenticationManager: new DefaultClaimsAuthenticationManager());

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return RedirectToAction("Index", new { name = saml2AuthnResponse.ClaimsIdentity.Name });
        }
    }
}