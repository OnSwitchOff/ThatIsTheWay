using ExpenseService.Models;
using Microsoft.EntityFrameworkCore;

namespace ExpenseService.Data
{
    namespace ExpenseService.Data
    {
        public class ExpenseDbContext : DbContext
        {
            public ExpenseDbContext(DbContextOptions<ExpenseDbContext> options) : base(options) { }

            public DbSet<Expense> Expenses { get; set; } = null!;
        }
    }
}
