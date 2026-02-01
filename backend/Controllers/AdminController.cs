using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "SystemAdministrator")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IItemTemplateRepository _templateRepository;

    public AdminController(AppDbContext context, IItemTemplateRepository templateRepository)
    {
        _context = context;
        _templateRepository = templateRepository;
    }

    /// <summary>
    /// Gets all tenants with usage statistics.
    /// </summary>
    [HttpGet("tenants")]
    public async Task<ActionResult<IEnumerable<TenantSummaryResponse>>> GetTenants()
    {
        var tenants = await _context.Tenants
            .Select(t => new TenantSummaryResponse
            {
                TenantId = t.Id,
                Name = t.Name,
                UserCount = t.TenantUsers.Count,
                CollectionCount = t.Collections.Count,
                ItemCount = _context.Items.Count(i => i.TenantId == t.Id),
                ImageCount = 0,
                CreatedAt = t.CreatedAt
            })
            .OrderBy(t => t.Name)
            .ToListAsync();

        // Calculate image counts client-side (Images is a JSON column, can't be counted in SQL)
        var tenantIds = tenants.Select(t => t.TenantId).ToList();
        var items = await _context.Items
            .Where(i => tenantIds.Contains(i.TenantId))
            .Select(i => new { i.TenantId, ImageCount = i.Images.Count })
            .ToListAsync();

        var imageCounts = items
            .GroupBy(i => i.TenantId)
            .ToDictionary(g => g.Key, g => g.Sum(i => i.ImageCount));

        foreach (var tenant in tenants)
        {
            if (imageCounts.TryGetValue(tenant.TenantId, out var count))
            {
                tenant.ImageCount = count;
            }
        }

        return Ok(tenants);
    }

    /// <summary>
    /// Deletes a tenant and all associated data.
    /// </summary>
    [HttpDelete("tenants/{id}")]
    public async Task<IActionResult> DeleteTenant(int id)
    {
        var tenant = await _context.Tenants
            .Include(t => t.Collections)
                .ThenInclude(c => c.Items)
            .Include(t => t.Collections)
                .ThenInclude(c => c.Categories)
            .Include(t => t.TenantUsers)
            .FirstOrDefaultAsync(t => t.Id == id);

        if (tenant is null)
        {
            return NotFound();
        }

        // Delete all related data (cascading should handle most, but be explicit)
        _context.Tenants.Remove(tenant);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    /// <summary>
    /// Gets all users, optionally filtered by email.
    /// </summary>
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<UserSummaryResponse>>> GetUsers([FromQuery] string? email = null)
    {
        var query = _context.Users
            .Include(u => u.ActiveTenant)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(email))
        {
            query = query.Where(u => u.Email.Contains(email));
        }

        var users = await query
            .Select(u => new UserSummaryResponse
            {
                UserId = u.Id,
                Email = u.Email,
                TenantId = u.ActiveTenantId,
                TenantName = u.ActiveTenant != null ? u.ActiveTenant.Name : "",
                IdentityProvider = u.IdentityProvider.ToString(),
                IsSystemAdministrator = u.IsSystemAdministrator,
                CreatedAt = u.CreatedAt
            })
            .OrderBy(u => u.Email)
            .ToListAsync();

        return Ok(users);
    }

    /// <summary>
    /// Deletes a user.
    /// </summary>
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    /// <summary>
    /// Sets the system administrator status for a user.
    /// </summary>
    [HttpPut("users/{id}/admin")]
    public async Task<ActionResult<UserSummaryResponse>> SetAdminStatus(int id, SetAdminStatusRequest request)
    {
        var user = await _context.Users
            .Include(u => u.ActiveTenant)
            .FirstOrDefaultAsync(u => u.Id == id);

        if (user is null)
        {
            return NotFound();
        }

        user.IsSystemAdministrator = request.IsSystemAdministrator;
        await _context.SaveChangesAsync();

        return Ok(new UserSummaryResponse
        {
            UserId = user.Id,
            Email = user.Email,
            TenantId = user.ActiveTenantId,
            TenantName = user.ActiveTenant?.Name ?? "",
            IdentityProvider = user.IdentityProvider.ToString(),
            IsSystemAdministrator = user.IsSystemAdministrator,
            CreatedAt = user.CreatedAt
        });
    }

    /// <summary>
    /// Gets all system templates (TenantId = null).
    /// </summary>
    [HttpGet("templates")]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetSystemTemplates()
    {
        var templates = await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .Where(t => t.TenantId == null)
            .OrderBy(t => t.Name)
            .ToListAsync();

        var response = templates.Select(ItemTemplateResponse.FromItemTemplate);
        return Ok(response);
    }

    /// <summary>
    /// Creates a new system template.
    /// </summary>
    [HttpPost("templates")]
    public async Task<ActionResult<ItemTemplateResponse>> CreateSystemTemplate(SystemTemplateRequest request)
    {
        var template = new ItemTemplate
        {
            TenantId = null, // System template
            Name = request.Name,
            Description = request.Description,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        var sortOrder = 0;
        foreach (var prop in request.Properties)
        {
            template.Properties.Add(new ItemTemplateProperty
            {
                Category = prop.Category,
                Name = prop.Name,
                SortOrder = sortOrder++
            });
        }

        _context.ItemTemplates.Add(template);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetSystemTemplate), new { id = template.Id }, 
            ItemTemplateResponse.FromItemTemplate(template));
    }

    /// <summary>
    /// Gets a specific system template.
    /// </summary>
    [HttpGet("templates/{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> GetSystemTemplate(int id)
    {
        var template = await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .FirstOrDefaultAsync(t => t.Id == id && t.TenantId == null);

        if (template is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(template));
    }

    /// <summary>
    /// Updates a system template.
    /// </summary>
    [HttpPut("templates/{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateSystemTemplate(int id, SystemTemplateRequest request)
    {
        var template = await _context.ItemTemplates
            .Include(t => t.Properties)
            .FirstOrDefaultAsync(t => t.Id == id && t.TenantId == null);

        if (template is null)
        {
            return NotFound();
        }

        template.Name = request.Name;
        template.Description = request.Description;
        template.UpdatedAt = DateTime.UtcNow;

        // Replace properties
        _context.ItemTemplateProperties.RemoveRange(template.Properties);
        
        var sortOrder = 0;
        foreach (var prop in request.Properties)
        {
            template.Properties.Add(new ItemTemplateProperty
            {
                ItemTemplateId = template.Id,
                Category = prop.Category,
                Name = prop.Name,
                SortOrder = sortOrder++
            });
        }

        await _context.SaveChangesAsync();

        return Ok(ItemTemplateResponse.FromItemTemplate(template));
    }

    /// <summary>
    /// Deletes a system template.
    /// </summary>
    [HttpDelete("templates/{id}")]
    public async Task<IActionResult> DeleteSystemTemplate(int id)
    {
        var template = await _context.ItemTemplates
            .FirstOrDefaultAsync(t => t.Id == id && t.TenantId == null);

        if (template is null)
        {
            return NotFound();
        }

        _context.ItemTemplates.Remove(template);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}
