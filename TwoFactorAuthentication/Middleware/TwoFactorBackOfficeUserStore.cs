using System.Linq;
using System.Threading.Tasks;
using Umbraco.Core;
using Umbraco.Core.Models.Identity;
using Umbraco.Core.Security;
using Umbraco.Core.Services;

namespace TwoFactorAuthentication.Middleware
{
    /// <summary>
    /// Subclass the default BackOfficeUserManager and extend it to support 2FA
    /// </summary>
    internal class TwoFactorBackOfficeUserStore : BackOfficeUserStore
    {
        public TwoFactorBackOfficeUserStore(IUserService userService, IExternalLoginService externalLoginService, 
            IEntityService entityService, MembershipProviderBase usersMembershipProvider)
            : base(userService, entityService, externalLoginService, usersMembershipProvider)
        { }

        /// <summary>
        /// Override to support setting whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"/><param name="enabled"/>
        /// <returns/>
        /// <remarks>
        /// This method is NOT designed to persist data! It's just meant to assign it, just like this
        /// </remarks>
        public override Task SetTwoFactorEnabledAsync(BackOfficeIdentityUser user, bool enabled)
        {
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        /// <summary>
        /// Returns whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public override Task<bool> GetTwoFactorEnabledAsync(BackOfficeIdentityUser user)
        {
            return Task.FromResult(true);
        }
    }
}