using Ekin.Auth.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Ekin.Auth.Db
{

    public class Operations : IDisposable
    {
        private AuthenticationDb _db;

        private UserManager<IdentityUser> _userManager;
        private RoleManager<IdentityRole> _roleManager;

        #region Constructors

        public Operations() : this(new AuthenticationDb())
        {

        }

        public Operations(AuthenticationDb context)
        {
            if (context == null)
            {
                _db = new AuthenticationDb();
            }
            else
            {
                _db = context;
            }
            _userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_db));
            _roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_db));
        }

        #endregion

        #region User manager operations

        public async Task<IdentityResult> RegisterUser(IdentityUser user, string password)
        {
            IdentityResult result = await _userManager.CreateAsync(user, password);
            if (result.Succeeded && !String.IsNullOrWhiteSpace(Settings.DefaultUserRole))
            {
                IdentityResult roleResult = await AddUserToRole(user.Id, Settings.DefaultUserRole);
                return roleResult;
            }
            return result;
        }

        public async Task<IdentityUser> FindUser(string userName, string password)
        {
            return await _userManager.FindAsync(userName, password);
        }

        public async Task<IdentityUser> FindUser(string userName)
        {
            return await _userManager.FindByNameAsync(userName);
        }

        public async Task<IdentityUser> FindById(string Id)
        {
            return await _userManager.FindByIdAsync(Id);
        }

        public async Task<IdentityUser> FindUserByEmail(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        public async Task<IdentityUser> GetCurrentUser()
        {
            return await FindUser(HttpContext.Current.User.Identity.Name);
        }

        public async Task<IdentityUser> FindAsync(UserLoginInfo loginInfo)
        {
            return await _userManager.FindAsync(loginInfo);
        }

        public async Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            return await _userManager.CreateAsync(user);
        }

        public async Task<IdentityResult> AddLoginAsync(string userId, UserLoginInfo login)
        {
            return await _userManager.AddLoginAsync(userId, login);
        }

        public async Task<string> GetPasswordResetToken(string userId)
        {
            SetPasswordResetToken();
            return await _userManager.GeneratePasswordResetTokenAsync(userId);
        }

        public async Task<IdentityResult> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            SetPasswordResetToken();
            return await _userManager.ResetPasswordAsync(userId, token, newPassword);
        }

        public async Task<string> GetEmailConfirmationToken(string userId)
        {
            SetEmailConfirmationToken();
            return await _userManager.GenerateEmailConfirmationTokenAsync(userId);
        }

        public async Task<IdentityResult> ConfirmEmailAsync(string userId, string token)
        {
            SetEmailConfirmationToken();
            return await _userManager.ConfirmEmailAsync(userId, token);
        }

        private void SetPasswordResetToken()
        {
            var provider = new DpapiDataProtectionProvider(Settings.AppName);
            _userManager.UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(provider.Create("ResetPassword"));
        }

        private void SetEmailConfirmationToken()
        {
            var provider = new DpapiDataProtectionProvider(Settings.AppName);
            _userManager.UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(provider.Create("Confirmation"));
        }

        public async Task<bool> DeleteUser(string UserId)
        {
            IdentityUser user = await FindById(UserId);
            if (user == null)
                return false;

            return await _userManager.DeleteAsync(user) == IdentityResult.Success;
        }

        #endregion

        #region Refresh Token

        public async Task<bool> AddRefreshToken(RefreshToken token)
        {

           //var existingToken = _db.RefreshTokens.Where(r => r.Subject == token.Subject && r.ClientId == token.ClientId).SingleOrDefault();
            var existingToken = _db.RefreshTokens.Where(r => r.Subject == token.Subject && r.ClientId == token.ClientId).FirstOrDefault();

            if (existingToken != null)
           {
             var result = await RemoveRefreshToken(existingToken);
           }
          
            _db.RefreshTokens.Add(token);

            return await _db.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveRefreshToken(string refreshTokenId)
        {
           var refreshToken = await _db.RefreshTokens.FindAsync(refreshTokenId);

           if (refreshToken != null) {
               _db.RefreshTokens.Remove(refreshToken);
               return await _db.SaveChangesAsync() > 0;
           }

           return false;
        }

        public async Task<bool> RemoveRefreshToken(RefreshToken refreshToken)
        {
            _db.RefreshTokens.Remove(refreshToken);
             return await _db.SaveChangesAsync() > 0;
        }

        public async Task<RefreshToken> FindRefreshToken(string refreshTokenId)
        {
            var refreshToken = await _db.RefreshTokens.FindAsync(refreshTokenId);

            return refreshToken;
        }

        public List<RefreshToken> GetAllRefreshTokens()
        {
             return  _db.RefreshTokens.ToList();
        }

        #endregion

        #region Client operations

        public async Task<bool> InitializeClients()
        {
            if (!_db.Clients.Any())
            {
                _db.Clients.AddRange(Ekin.Auth.Settings.Clients);
                return await _db.SaveChangesAsync() > 0;
            }
            else
                return true;
        }

        public Client FindClient(string clientId)
        {
            return _db.Clients.Find(clientId);
        }

        #endregion

        #region Role manager

        public async Task<IList<string>> UserRoles(string userId)
        {
            return await _userManager.GetRolesAsync(userId);
        }

        public async Task<IdentityResult> AddRole(string roleName)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                return _roleManager.Create(new IdentityRole(roleName));
            }
            return null;
        }

        public async Task<IdentityRole> GetRole(string roleName)
        {
            return await _roleManager.FindByNameAsync(roleName);
        }

        public async Task<IdentityResult> AddUserToRole(string userId, string roleName)
        {
            return await _userManager.AddToRoleAsync(userId, roleName);
        }

        public async Task<bool> InitializeRoles()
        {
            if (!_db.Roles.Any())
            {
                foreach (string roleName in Settings.Roles)
                {
                    _db.Roles.Add(new IdentityRole(roleName));
                }
                await _db.SaveChangesAsync();
            }

            if (Settings.CreateDefaultAdmin)
            {
                IdentityUser user = _userManager.FindByName(Settings.DefaultAdminUsername);
                if (user == null)
                {
                    IdentityUser newUser = new IdentityUser()
                    {
                        UserName = Settings.DefaultAdminUsername,
                        Email = Settings.DefaultAdminEmail
                    };
                    await _userManager.CreateAsync(newUser, Settings.DefaultAdminPassword);
                    await _userManager.SetLockoutEnabledAsync(newUser.Id, false);
                    await _userManager.AddToRoleAsync(newUser.Id, Settings.DefaultAdminRole);
                }
            }

            return true;
        }

        #endregion

        #region Get accounts by ids

        public List<IdentityUser> GetUsers(List<string> ids)
        {
            return _db.Users.Where(i => ids.Contains(i.Id)).ToList();
        }

        public List<AspNetUser> GetAccounts(List<string> ids)
        {
            List<IdentityUser> users = GetUsers(ids);
            if (users != null)
            {
                List<AspNetUser> results = new List<AspNetUser> { };
                foreach (IdentityUser iduser in users)
                {
                    AspNetUser modelUser = GetAspNetUser(iduser);
                    results.Add(modelUser);
                }
                return results;
            }
            return null;
        }

        public AspNetUser GetAccount(string id)
        {
            IdentityUser iduser = _db.Users.Where(i => i.Id == id).FirstOrDefault();
            if (iduser != null)
            {
                AspNetUser modelUser = GetAspNetUser(iduser);
                return modelUser;
            }
            return null;
        }

        #endregion

        #region Users in Roles

        public async Task<List<AspNetUser>> GetAccountsByRoleName(string roleName)
        {
            IdentityRole role = await GetRole(roleName);
            if (role == null) return null;
            return await GetAccountsByRoleId(role.Id);
        }

        public async Task<List<AspNetUser>> GetAccountsByRoleId(string roleId)
        {
            List<IdentityUser> users = _db.Users.Where(x => x.Roles.Select(y => y.RoleId).Contains(roleId)).ToList();
            if (users != null)
            {
                List<AspNetUser> results = new List<AspNetUser> { };
                foreach (IdentityUser iduser in users)
                {
                    AspNetUser modelUser = GetAspNetUser(iduser);
                    results.Add(modelUser);
                }
                return results;
            }
            return null;
        }

        public async Task<List<string>> GetAccountIdsByRoleName(string roleName)
        {
            if (string.IsNullOrEmpty(roleName)) return null;
            IdentityRole role = await GetRole(roleName);
            if (role == null) return null;
            return _db.Users.Where(x => x.Roles.Select(y => y.RoleId).Contains(role.Id)).Select(i => i.Id).ToList();
        }

        #endregion

        public async Task<AspNetUser> GetCurrentAspNetUser()
        {
            IdentityUser idUser = await GetCurrentUser();
            if (idUser != null)
            {
                return GetAspNetUser(idUser);
            }
            else
            {
                return null;
            }
        }

        public AspNetUser GetAspNetUser(IdentityUser idUser)
        {
            return new AspNetUser()
            {
                IdentityUserId = idUser.Id,
                UserName = idUser.UserName,
                Email = idUser.Email,
                EmailConfirmed = idUser.EmailConfirmed,
                PhoneNumber = idUser.PhoneNumber,
                PhoneNumberConfirmed = idUser.PhoneNumberConfirmed,
                TwoFactorEnabled = idUser.TwoFactorEnabled
            };
        }

        public void Dispose()
        {
            _db.Dispose();
            _userManager.Dispose();
            _roleManager.Dispose();
        }
    }
}