using backend.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IPublishManagerService
{
    // Preflight and Execute
    Task<PreflightResponse> PreflightAsync(int workspaceId, PreflightRequest request);
    Task<ExecuteResponse> ExecuteAsync(int workspaceId, ExecuteRequest request);

    // Effective visibility computation (migrated from IVisibilityService)
    void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories);
    void ComputeEffectiveVisibility(Item item, Collection collection, Category? category);
    void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection);
    void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories);
}
