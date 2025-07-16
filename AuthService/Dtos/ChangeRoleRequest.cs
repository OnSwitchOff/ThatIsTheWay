using AuthService.Models;

namespace AuthService.Dtos
{
    public class ChangeRoleRequest
    {
        public Guid UserId { get; set; }
        public Role NewRole { get; set; }
    }
}
