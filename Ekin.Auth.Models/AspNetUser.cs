using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace Ekin.Auth.Models
{
    public class AspNetUser
    {
        //[Key]
        //public string Id { get; set; }

        [Display(Name = "User name")]
        public string UserName { get; set; }

        [Required]
        [JsonIgnore]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [JsonIgnore]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [DataType(DataType.EmailAddress)]
        [Display(Name = "Email")]
        [EmailAddress]
        public string Email { get; set; }

        [DataType(DataType.PhoneNumber)]
        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }

        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }

        [JsonIgnore]
        public string IdentityUserId { get; set; }

        //private IdentityUser _identityUser { get; set; }
        //[JsonIgnore]
        //[NotMapped]
        //public IdentityUser IdentityUser
        //{
        //    get
        //    {
        //        {
        //            if (_identityUser == null)
        //            {
        //                _identityUser = new IdentityUser();     // This will generate a new GUID as Id
        //                IdentityUserId = _identityUser.Id;
        //            }
        //            if (Settings.UseEmailAsUsername)
        //            {
        //                _identityUser.UserName = this.Email;
        //            }
        //            else
        //            {
        //                _identityUser.UserName = this.UserName;
        //            }
        //            _identityUser.Email = this.Email;
        //            _identityUser.EmailConfirmed = false;
        //            _identityUser.PhoneNumber = this.PhoneNumber;
        //            _identityUser.PhoneNumberConfirmed = false;
        //            _identityUser.TwoFactorEnabled = false;
        //            //_identityUser.Roles.Add(new IdentityRole(Settings.DefaultRole));

        //            return _identityUser;
        //        }
        //    }
        //    set
        //    {
        //        if (value != null)
        //        {
        //            _identityUser = value;

        //            IdentityUserId = _identityUser.Id;
        //            UserName = _identityUser.UserName;
        //            Email = _identityUser.Email;
        //            EmailConfirmed = _identityUser.EmailConfirmed;
        //            PhoneNumber = _identityUser.PhoneNumber;
        //            PhoneNumberConfirmed = _identityUser.PhoneNumberConfirmed;
        //            TwoFactorEnabled = _identityUser.TwoFactorEnabled;
        //            // TODO: Add Roles here
        //            //Roles = _identityUser.Roles;
        //        }
        //        else
        //        {
        //            _identityUser = null;
        //            IdentityUserId = string.Empty;
        //        }
        //    }
        //}

        //public static async Task<AspNetUser> GetCurrentUser()
        //{
        //    AspNetUser user = new AspNetUser();

        //    // Populate inherited AspNetUser fields
        //    IdentityUser idUser = null;
        //    using (Db.Operations _repo = new Db.Operations())
        //    {
        //        idUser = await _repo.GetCurrentUser();
        //    }
        //    if (idUser != null)
        //    {
        //        user.IdentityUser = idUser;
        //    }

        //    return user;
        //}
    }

}