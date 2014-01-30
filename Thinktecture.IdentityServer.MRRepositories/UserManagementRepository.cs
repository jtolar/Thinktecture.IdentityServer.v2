using BrockAllen.MembershipReboot;
using BrockAllen.MembershipReboot.Ef;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.MRRepositories
{
    public class UserManagementRepository : IUserManagementRepository
    {
        private readonly IGroupQuery _groupQuery;
        private readonly GroupService _groupService;
        private readonly IUserAccountQuery _userQuery;
        private readonly UserAccountService _userService;

        public UserManagementRepository()
        {
            SecuritySettings settings = SecuritySettings.FromConfiguration();
            if (settings == null)
                throw new ConfigurationErrorsException("Unable to retrieve security settings from configuration.");

            settings.RequireAccountVerification = false;
            var config = new MembershipRebootConfiguration(settings);
            var userAccountRepository = new DefaultUserAccountRepository();
            _userService = new UserAccountService(config, userAccountRepository);
            _userQuery = userAccountRepository;

            var groupRepository = new DefaultGroupRepository();
            _groupService = new GroupService(config.DefaultTenant, groupRepository);
            _groupQuery = groupRepository;
        }

        public UserManagementRepository(UserAccountService userSvc, GroupService groupSvc)
        {
            _userService = userSvc;
            _groupService = groupSvc;
        }

        #region IUserManagementRepository

        public void CreateRole(string roleName)
        {
            _groupService.Create(roleName);
        }

        public void CreateUser(string userName, string password, string email = null)
        {
            _userService.CreateAccount(userName, password, email);
        }

        public void DeleteRole(string roleName)
        {
            Group grp = _groupService.Get(roleName);
            if (grp != null)
            {
                _groupService.Delete(grp.ID);
            }
        }

        public void DeleteUser(string userName)
        {
            UserAccount user = _userService.GetByUsername(userName);
            if (user != null)
            {
                _userService.DeleteAccount(user.ID);
            }
        }

        public IEnumerable<string> GetRoles()
        {
            return _groupQuery.GetRoleNames(_userService.Configuration.DefaultTenant);
        }

        public IEnumerable<string> GetRolesForUser(string userName)
        {
            UserAccount user = _userService.GetByUsername(userName);
            if (user != null)
            {
                return user.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value);
            }
            return Enumerable.Empty<string>();
        }

        public IEnumerable<string> GetUsers(int start, int count, out int totalCount)
        {
            return
                _userQuery.Query(_userService.Configuration.DefaultTenant, null, start, count, out totalCount)
                    .Select(x => x.Username);
        }

        public IEnumerable<string> GetUsers(string filter, int start, int count, out int totalCount)
        {
            return
                _userQuery.Query(_userService.Configuration.DefaultTenant, filter, start, count, out totalCount)
                    .Select(x => x.Username);
        }

        public void SetPassword(string userName, string password)
        {
            UserAccount user = _userService.GetByUsername(userName);
            if (user != null)
            {
                _userService.SetPassword(user.ID, password);
            }
        }

        public void SetRolesForUser(string userName, IEnumerable<string> roles)
        {
            UserAccount user = _userService.GetByUsername(userName);
            if (user != null)
            {
                _userService.RemoveClaim(user.ID, ClaimTypes.Role);
                if (roles != null)
                {
                    foreach (string role in roles)
                    {
                        _userService.AddClaim(user.ID, ClaimTypes.Role, role);
                    }
                }
            }
        }

        #endregion
    }
}