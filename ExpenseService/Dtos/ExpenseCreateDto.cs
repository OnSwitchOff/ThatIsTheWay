using System.ComponentModel.DataAnnotations;

namespace ExpenseService.Dtos
{
    public class ExpenseCreateDto
    {
        [Range(0.01, double.MaxValue, ErrorMessage = "Amount must be positive")]
        public decimal Amount { get; set; }

        [Required(ErrorMessage = "Category is required")]
        public required string Category { get; set; }

        public string? Description { get; set; }
    }
}
