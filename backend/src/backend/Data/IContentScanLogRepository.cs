using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IContentScanLogRepository
{
    Task<ContentScanLog> CreateAsync(ContentScanLog scanLog);
    Task<ContentScanLog?> GetByIdAsync(Guid id);
    Task UpdateAsync(ContentScanLog scanLog);
}
