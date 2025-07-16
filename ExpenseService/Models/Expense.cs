using System.ComponentModel.DataAnnotations;

namespace ExpenseService.Models
{
    public class Expense
    {
        public Guid UserId { get; set; }

        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        public decimal Amount { get; set; } 
        public required string Category { get; set; }
        public DateTime Date { get; set; } = DateTime.Now;
        public string? Description { get; set; }
    }
}

