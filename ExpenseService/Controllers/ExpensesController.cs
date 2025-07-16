using ExpenseService.Data;
using ExpenseService.Data.ExpenseService.Data;
using ExpenseService.Dtos;
using ExpenseService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

[ApiController]
[Route("api/[controller]")]
public class ExpensesController : ControllerBase
{
    private readonly ExpenseDbContext _context;

    public ExpensesController(ExpenseDbContext context)
    {
        _context = context;
    }

    [Authorize]
    [HttpGet]
    public ActionResult<IEnumerable<Expense>> GetAll()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var expenses = _context.Expenses
            .Where(e => e.UserId == Guid.Parse(userId!))
            .ToList();

        return Ok(expenses);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Expense>> GetById(Guid id)
    {
        var expense = await _context.Expenses.FindAsync(id);
        if (expense == null)
            return NotFound();
        return Ok(expense);
    }

    [Authorize]
    [HttpPost]
    public ActionResult<Expense> Create(ExpenseCreateDto dto)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        var expense = new Expense
        {
            Id = Guid.NewGuid(),
            Amount = dto.Amount,
            Category = dto.Category,
            Date = DateTime.UtcNow,
            Description = dto.Description,
            UserId = Guid.Parse(userId)
        };

        _context.Expenses.Add(expense);
        _context.SaveChanges();

        return CreatedAtAction(nameof(GetById), new { id = expense.Id }, expense);
    }

    [HttpDelete("{id}")]
    public async Task<ActionResult> Delete(Guid id)
    {
        var expense = await _context.Expenses.FindAsync(id);
        if (expense == null)
            return NotFound();

        _context.Expenses.Remove(expense);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}
