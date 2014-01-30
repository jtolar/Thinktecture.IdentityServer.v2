using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using BrockAllen.MembershipReboot;
using BrockAllen.MembershipReboot.Ef;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.MRRepositories
{
    public class UserRepository : IUserRepository
    {
        private readonly UserAccountService _userService;

        public UserRepository()
        {
            SecuritySettings settings = SecuritySettings.FromConfiguration();
            settings.RequireAccountVerification = false;
            var config = new MembershipRebootConfiguration(settings);
            var userAccountRepository = new DefaultUserAccountRepository();
            _userService = new UserAccountService(config, userAccountRepository);
        }

        public UserRepository(UserAccountService userSvc)
        {
            _userService = userSvc;
        }

        #region IUserRepository

        public IEnumerable<string> GetRoles(string userName)
        {
            UserAccount user = _userService.GetByUsername(userName);
            if (user != null)
            {
                return user.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value);
            }
            return Enumerable.Empty<string>();
        }

        public bool ValidateUser(X509Certificate2 clientCertificate, out string userName)
        {
            UserAccount user;
            if (_userService.AuthenticateWithCertificate(clientCertificate, out user))
            {
                userName = user.Username;
                return true;
            }

            userName = null;
            return false;
        }

        public bool ValidateUser(string userName, string password)
        {
            return _userService.Authenticate(userName, password);
        }

        #endregion
    }
}