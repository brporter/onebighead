using OneBigHead.Server.Services.Exports;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ExportController(IWorkspaceExportService exports) : ApiControllerBase
{
    [HttpGet]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<IActionResult> ExportData()
    {
        var archive = await exports.ExportAsync(GetWorkspaceId());
        return File(archive.Data, "application/zip", archive.FileName);
    }
}
