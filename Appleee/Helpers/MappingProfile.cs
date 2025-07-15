using AutoMapper;
using ORAA.DTO;
using ORAA.Models;
using ORAA.Request;

namespace ORAA.Helpers
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Admin
          

            // User
            CreateMap<User, AddUser>().ReverseMap();
            CreateMap<User, UserDTO>().ReverseMap();

        }
    }
}
