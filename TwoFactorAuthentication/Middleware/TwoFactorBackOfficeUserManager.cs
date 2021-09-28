using System;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Umbraco.Core.Configuration;
using Umbraco.Core.Models.Identity;
using Umbraco.Core.Security;
using Umbraco.Core.Services;
using Umbraco.Web;
using Umbraco.Web.Security.Identity;

namespace TwoFactorAuthentication.Middleware
{
    /// <summary>
    /// Subclass the default BackOfficeUserManager and extend it to support 2FA
    /// </summary>
    internal class TwoFactorBackOfficeUserManager : BackOfficeUserManager, IUmbracoBackOfficeTwoFactorOptions
    {
        public TwoFactorBackOfficeUserManager(IUserStore<BackOfficeIdentityUser, int> store) : base(store)
        { }

        /// <summary>
        /// Creates a BackOfficeUserManager instance with all default options and the default BackOfficeUserManager 
        /// </summary>
        /// <param name="options"></param>
        /// <param name="userService"></param>
        /// <param name="entityService"></param>
        /// <param name="externalLoginService"></param>
        /// <param name="membershipProvider"></param>
        /// <returns></returns>
        public static TwoFactorBackOfficeUserManager Create(
            IdentityFactoryOptions<TwoFactorBackOfficeUserManager> options,
            IUserService userService,
            IEntityService entityService,
            IExternalLoginService externalLoginService,
            MembershipProviderBase membershipProvider)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (userService == null) throw new ArgumentNullException("userService");
            if (entityService == null) throw new ArgumentNullException("entityService");
            if (externalLoginService == null) throw new ArgumentNullException("externalLoginService");

            var manager = new TwoFactorBackOfficeUserManager(new TwoFactorBackOfficeUserStore(userService, externalLoginService, entityService, membershipProvider));
            manager.InitUserManager(manager, membershipProvider, options.DataProtectionProvider, UmbracoConfig.For.UmbracoSettings().Content);

            //Here you can specify the 2FA providers that you want to implement
            var dataProtectionProvider = options.DataProtectionProvider;

            //manager.RegisterTwoFactorProvider(Constants.YubiKeyProviderName, 
            //    new TwoFactorValidationProvider(dataProtectionProvider.Create(Constants.YubiKeyProviderName)));

            //manager.RegisterTwoFactorProvider(Constants.GoogleAuthenticatorProviderName, 
            //    new TwoFactorValidationProvider(dataProtectionProvider.Create(Constants.GoogleAuthenticatorProviderName)));


            manager.RegisterTwoFactorProvider("EmailPassword", new AcceptAnyCodeProvider(dataProtectionProvider.Create("EmailPassword")));

            return manager;
        }

        /// <summary>
        /// Silly IUserTokenProvider for this Demo to be used for the 2FA provider, this will generate a code but not send it anywhere 
        /// (which is what the base class does), and then we override the ValidateAsync method to validate any code given - do not actually use this!
        /// </summary>
        public class AcceptAnyCodeProvider : DataProtectorTokenProvider<BackOfficeIdentityUser, int>, IUserTokenProvider<BackOfficeIdentityUser, int>
        {
            public AcceptAnyCodeProvider(IDataProtector protector)
                : base(protector)
            {
            }

            /// <summary>
            /// Explicitly implement this interface method - which overrides the base class's implementation
            /// </summary>
            /// <param name="purpose"></param>
            /// <param name="token"></param>
            /// <param name="manager"></param>
            /// <param name="user"></param>
            /// <returns></returns>
            Task<bool> IUserTokenProvider<BackOfficeIdentityUser, int>.ValidateAsync(string purpose, string token, UserManager<BackOfficeIdentityUser, int> manager, BackOfficeIdentityUser user)
            {
                return Task.FromResult(true); // need to remove this

                if (HttpContext.Current.Session["newNumber"] != null && !string.IsNullOrEmpty(token) &&
                    token == Convert.ToString(HttpContext.Current.Session["newNumber"]))
                {
                    return Task.FromResult(true);
                }
                return Task.FromResult(false);
            }
        }



        /// <inheritdoc />
        /// <summary>
        /// Override to return true
        /// </summary>
        public override bool SupportsUserTwoFactor
        {
            get { return true; }
        }

        /// <summary>
        /// Return the view for the 2FA screen
        /// </summary>
        /// <param name="owinContext"></param>
        /// <param name="umbracoContext"></param>
        /// <param name="username"></param>
        /// <returns></returns>
        public string GetTwoFactorView(IOwinContext owinContext, UmbracoContext umbracoContext, string username)
        {

            Random _rnd = new Random();
            var newNumber = _rnd.Next(100000, 999999).ToString();
            

            //HttpContext.Current.Session["newNumber"] = newNumber;

            //session is not working, need to find out a way to store password

            
            //Send email to user this newNumber

            return "../App_Plugins/2FactorAuthentication/2fa-login.html";
        }
    }
}