using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Categories;

public interface ICategoryWriteService
{
    Task<CategoryWriteResult<CategoryResponse>> CreateAsync(int workspaceId, CreateCategoryRequest request, CancellationToken cancellationToken = default);
    Task<CategoryWriteResult<CategoryResponse>> UpdateAsync(int categoryId, int workspaceId, UpdateCategoryRequest request, CancellationToken cancellationToken = default);
    Task<CategoryWriteResult<int>> ReorderAsync(int workspaceId, ReorderCategoriesRequest request, CancellationToken cancellationToken = default);
    Task<CategoryWriteResult<bool>> DeleteAsync(int categoryId, int workspaceId, CancellationToken cancellationToken = default);
}

public enum CategoryWriteFailure { Invalid, NotFound, Forbidden, Conflict }

public sealed record CategoryWriteError(CategoryWriteFailure Kind, string Message);

/// <summary>A committed value or a rejected operation; rejected operations make no changes.</summary>
public sealed class CategoryWriteResult<T>
{
    private CategoryWriteResult(T? value, CategoryWriteError? error) { Value = value; Error = error; }
    public T? Value { get; }
    public CategoryWriteError? Error { get; }
    public static CategoryWriteResult<T> Success(T value) => new(value, null);
    public static CategoryWriteResult<T> Failure(CategoryWriteError error) => new(default, error);
}
