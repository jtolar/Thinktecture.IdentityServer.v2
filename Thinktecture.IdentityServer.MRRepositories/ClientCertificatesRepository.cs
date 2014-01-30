using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using BrockAllen.MembershipReboot;
using BrockAllen.MembershipReboot.Ef;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.MRRepositories
{
    public class ClientCertificatesRepository : IClientCertificatesRepository
    {
        private readonly IUserAccountQuery _userQuery;
        private readonly UserAccountService _userService;

        public ClientCertificatesRepository()
        {
            SecuritySettings settings = SecuritySettings.FromConfiguration();
            settings.RequireAccountVerification = false;
            var config = new MembershipRebootConfiguration(settings);
            var userAccountRepository = new DefaultUserAccountRepository();
            _userService = new UserAccountService(config, userAccountRepository);
            _userQuery = userAccountRepository;
        }

        public ClientCertificatesRepository(UserAccountService userSvc)
        {
            _userService = userSvc;
        }

        #region IClientCertificatesRepository

        public void Add(ClientCertificate certificate)
        {
            UserAccount user = _userService.GetByUsername(certificate.UserName);
            if (user != null)
            {
                _userService.AddCertificate(user.ID, certificate.Thumbprint, certificate.Description);
            }
        }

        public void Delete(ClientCertificate certificate)
        {
            UserAccount user = _userService.GetByUsername(certificate.UserName);
            if (user != null)
            {
                _userService.RemoveCertificate(user.ID, certificate.Thumbprint);
            }
        }

        public IEnumerable<ClientCertificate> GetClientCertificatesForUser(string userName)
        {
            UserAccount user = _userService.GetByUsername(userName);
            if (user != null)
            {
                return
                    user.Certificates.Select(
                        x =>
                            new ClientCertificate
                            {
                                UserName = user.Username,
                                Thumbprint = x.Thumbprint,
                                Description = x.Subject
                            });
            }
            return Enumerable.Empty<ClientCertificate>();
        }

        public IEnumerable<string> List(int pageIndex, int pageSize)
        {
            if (pageIndex < 1) pageIndex = 1;
            if (pageSize < 0) pageSize = 10;
            int skip = pageSize*(pageIndex - 1);
            int totalCount;
            return
                _userQuery.Query(_userService.Configuration.DefaultTenant, null, skip, pageSize, out totalCount)
                    .Select(x => x.Username);
        }

        public bool SupportsWriteAccess
        {
            get { return true; }
        }

        public bool TryGetUserNameFromThumbprint(X509Certificate2 certificate, out string userName)
        {
            UserAccount user;
            if (_userService.AuthenticateWithCertificate(certificate, out user))
            {
                userName = user.Username;
                return true;
            }
            userName = null;
            return false;
        }

        #endregion
    }
}