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
    /// Gets all workspaces with usage statistics.
    /// </summary>
    [HttpGet("workspaces")]
    public async Task<ActionResult<IEnumerable<WorkspaceSummaryResponse>>> GetWorkspaces()
    {
        var workspaces = await _context.Workspaces
            .Select(w => new WorkspaceSummaryResponse
            {
                WorkspaceId = w.Id,
                Name = w.Name,
                UserCount = w.WorkspaceUsers.Count,
                CollectionCount = w.Collections.Count,
                ItemCount = _context.Items.Count(i => i.WorkspaceId == w.Id),
                ImageCount = 0,
                CreatedAt = w.CreatedAt
            })
            .OrderBy(w => w.Name)
            .ToListAsync();

        // Calculate image counts client-side (Images is a JSON column, can't be counted in SQL)
        var workspaceIds = workspaces.Select(w => w.WorkspaceId).ToList();
        var items = await _context.Items
            .Where(i => workspaceIds.Contains(i.WorkspaceId))
            .Select(i => new { i.WorkspaceId, ImageCount = i.Images.Count })
            .ToListAsync();

        var imageCounts = items
            .GroupBy(i => i.WorkspaceId)
            .ToDictionary(g => g.Key, g => g.Sum(i => i.ImageCount));

        foreach (var workspace in workspaces)
        {
            if (imageCounts.TryGetValue(workspace.WorkspaceId, out var count))
            {
                workspace.ImageCount = count;
            }
        }

        return Ok(workspaces);
    }

    /// <summary>
    /// Deletes a workspace and all associated data.
    /// </summary>
    [HttpDelete("workspaces/{id}")]
    public async Task<IActionResult> DeleteWorkspace(int id)
    {
        var workspace = await _context.Workspaces
            .Include(w => w.Collections)
                .ThenInclude(c => c.Items)
            .Include(w => w.Collections)
                .ThenInclude(c => c.Categories)
            .Include(w => w.WorkspaceUsers)
            .FirstOrDefaultAsync(w => w.Id == id);

        if (workspace is null)
        {
            return NotFound();
        }

        // Delete all related data (cascading should handle most, but be explicit)
        _context.Workspaces.Remove(workspace);
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
            .Include(u => u.ActiveWorkspace)
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
                WorkspaceId = u.ActiveWorkspaceId,
                WorkspaceName = u.ActiveWorkspace != null ? u.ActiveWorkspace.Name : "",
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
            .Include(u => u.ActiveWorkspace)
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
            WorkspaceId = user.ActiveWorkspaceId,
            WorkspaceName = user.ActiveWorkspace?.Name ?? "",
            IdentityProvider = user.IdentityProvider.ToString(),
            IsSystemAdministrator = user.IsSystemAdministrator,
            CreatedAt = user.CreatedAt
        });
    }

    /// <summary>
    /// Gets all system templates (WorkspaceId = null).
    /// </summary>
    [HttpGet("templates")]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetSystemTemplates()
    {
        var templates = await _context.ItemTemplates
            .Include(t => t.Properties.OrderBy(p => p.SortOrder))
            .Where(t => t.WorkspaceId == null)
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
            WorkspaceId = null, // System template
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
            .FirstOrDefaultAsync(t => t.Id == id && t.WorkspaceId == null);

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
            .FirstOrDefaultAsync(t => t.Id == id && t.WorkspaceId == null);

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
            .FirstOrDefaultAsync(t => t.Id == id && t.WorkspaceId == null);

        if (template is null)
        {
            return NotFound();
        }

        _context.ItemTemplates.Remove(template);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}
