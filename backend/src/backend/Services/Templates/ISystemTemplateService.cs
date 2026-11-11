using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Templates;

public interface ISystemTemplateService
{
    Task<IReadOnlyList<ItemTemplateResponse>> GetAllAsync();
    Task<ItemTemplateResponse?> GetAsync(int id);
    Task<ItemTemplateResponse> CreateAsync(SystemTemplateRequest request);
    Task<ItemTemplateResponse?> UpdateAsync(int id, SystemTemplateRequest request);
    Task<bool> DeleteAsync(int id);
}
