using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using BrockAllen.MembershipReboot;
using BrockAllen.MembershipReboot.Ef;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.MRRepositories
{
    public class ClaimsRepository : IClaimsRepository
    {
        private readonly UserAccountService _userService;

        public ClaimsRepository()
        {
            SecuritySettings settings = SecuritySettings.FromConfiguration();
            settings.RequireAccountVerification = false;
            var config = new MembershipRebootConfiguration(settings);
            var userAccountRepository = new DefaultUserAccountRepository();
            _userService = new UserAccountService(config, userAccountRepository);
        }

        public ClaimsRepository(UserAccountService userSvc)
        {
            _userService = userSvc;
        }

        #region IClaimsRepository

        public IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            UserAccount user = _userService.GetByUsername(principal.Identity.Name);
            if (user == null) throw new ArgumentException("Invalid user name");

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.ID.ToString("D"))
            };
            if (!String.IsNullOrWhiteSpace(user.Email))
                claims.Add(new Claim(ClaimTypes.Email, user.Email));

            if (!String.IsNullOrWhiteSpace(user.MobilePhoneNumber))
                claims.Add(new Claim(ClaimTypes.MobilePhone, user.MobilePhoneNumber));

            //var x509 = from c in user.Certificates
            //           select new Claim(ClaimTypes.X500DistinguishedName, c.Subject);
            //claims.AddRange(x509);
            List<Claim> otherClaims =
                (from uc in user.Claims
                    select new Claim(uc.Type, uc.Value)).ToList();

            claims.AddRange(otherClaims);

            return claims;
        }

        public IEnumerable<string> GetSupportedClaimTypes()
        {
            return
                new[] {ClaimTypes.Name, ClaimTypes.Email, ClaimTypes.MobilePhone, ClaimTypes.Role};
        }

        #endregion
    }
}