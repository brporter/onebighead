namespace OneBigHead.Server.Services.Exports;

/// <summary>The caller owns and must dispose the archive stream.</summary>
public sealed record WorkspaceExport(Stream Data, string FileName);

public interface IWorkspaceExportService
{
    Task<WorkspaceExport> ExportAsync(int workspaceId);
}
