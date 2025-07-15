using Microsoft.AspNetCore.Identity;
using ORAA.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using ORAA.Models;
using ORAA.Models.Apple;


namespace ORAA.Data
{
    public class DataContext : IdentityDbContext<User, IdentityRole<int>, int>
    {
        private readonly IConfiguration _configuration;

        public DataContext(DbContextOptions<DataContext> options, IConfiguration configuration)
            : base(options)
        {
            _configuration = configuration;
        }

     
        public DbSet<User> Users { get; set; }
        public DbSet<AppleUser> appeUsers { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer(_configuration.GetConnectionString("DefaultConnection"));
            }
        }
    }
}
