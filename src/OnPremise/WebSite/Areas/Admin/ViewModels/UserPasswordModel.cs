using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class UserPasswordModel
    {
        [Required]
// ReSharper disable Mvc.TemplateNotResolved
        [UIHint("HiddenInput")]
// ReSharper restore Mvc.TemplateNotResolved
        public string Username { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}