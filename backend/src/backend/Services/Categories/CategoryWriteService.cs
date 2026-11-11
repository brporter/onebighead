using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services.Categories;

public sealed class CategoryWriteService(IDbContextFactory<AppDbContext> contextFactory) : ICategoryWriteService
{
    public Task<CategoryWriteResult<CategoryResponse>> CreateAsync(int workspaceId, CreateCategoryRequest request, CancellationToken cancellationToken = default) =>
        SaveAsync(null, workspaceId, request.CollectionId, request.Name, request.Description, request.ParentCategoryId, request.ItemTemplateIds, cancellationToken);

    public Task<CategoryWriteResult<CategoryResponse>> UpdateAsync(int categoryId, int workspaceId, UpdateCategoryRequest request, CancellationToken cancellationToken = default) =>
        SaveAsync(categoryId, workspaceId, null, request.Name, request.Description, request.ParentCategoryId, request.ItemTemplateIds, cancellationToken);

    private Task<CategoryWriteResult<CategoryResponse>> SaveAsync(int? categoryId, int workspaceId, int? collectionId,
        string name, string? description, int? parentId, List<int>? templateIds, CancellationToken cancellationToken) =>
        ExecuteAsync<Category, CategoryResponse>(async context =>
        {
            Category? category = null;
            if (categoryId.HasValue)
            {
                category = await context.Categories.Include(c => c.CategoryItemTemplates)
                    .SingleOrDefaultAsync(c => c.Id == categoryId && c.WorkspaceId == workspaceId, cancellationToken);
                if (category is null) return Reject<Category>(CategoryWriteFailure.NotFound, "Category not found");
                if (category.IsSystem) return Reject<Category>(CategoryWriteFailure.Forbidden, "System categories cannot be modified.");
                collectionId = category.CollectionId;
            }

            var fieldError = CategoryEditPolicy.ValidateFields(name, description);
            if (fieldError != null) return Reject<Category>(CategoryWriteFailure.Invalid, fieldError);

            var collection = await context.Collections.SingleOrDefaultAsync(
                c => c.Id == collectionId && c.WorkspaceId == workspaceId, cancellationToken);
            if (collection is null)
                return Reject<Category>(categoryId.HasValue ? CategoryWriteFailure.NotFound : CategoryWriteFailure.Invalid, "Collection not found");

            var categories = await context.Categories.Where(c => c.CollectionId == collection.Id && c.WorkspaceId == workspaceId)
                .ToDictionaryAsync(c => c.Id, cancellationToken);
            if (!CategoryEditPolicy.IsValidParent(categoryId, parentId, categories))
                return Reject<Category>(CategoryWriteFailure.Invalid, "Invalid parent category. Choose a category in this collection outside the category's descendants.");

            var desiredTemplates = templateIds?.Distinct().ToList() ?? category?.CategoryItemTemplates
                .OrderBy(link => link.SortOrder).Select(link => link.ItemTemplateId).ToList() ?? [];
            var availableTemplateCount = await context.ItemTemplates.CountAsync(template => desiredTemplates.Contains(template.Id) &&
                (template.WorkspaceId == null || template.WorkspaceId == workspaceId), cancellationToken);
            if (availableTemplateCount != desiredTemplates.Count)
                return Reject<Category>(CategoryWriteFailure.Invalid, "One or more item templates are unavailable in this workspace.");

            if (category is null)
            {
                CategoryVisibility.Apply(categories.Values, collection);
                var parentPublic = parentId is int id ? categories[id].EffectiveIsPublic : collection.EffectiveIsPublic;
                category = new Category { WorkspaceId = workspaceId, CollectionId = collection.Id,
                    Visibility = parentPublic ? Visibility.Public : Visibility.Private };
                context.Categories.Add(category);
                categories.Add(category.Id, category);
            }

            category.Name = name.Trim();
            category.Description = description ?? string.Empty;
            category.ParentCategoryId = parentId;
            if (templateIds != null) ReplaceTemplates(context, category, desiredTemplates);
            CategoryVisibility.Apply(categories.Values, collection);
            return CategoryWriteResult<Category>.Success(category);
        }, category => CategoryResponse.FromCategory(category,
            category.CategoryItemTemplates.OrderBy(link => link.SortOrder).ThenBy(link => link.ItemTemplateId)
                .Select(link => link.ItemTemplateId).ToList()), cancellationToken);

    public Task<CategoryWriteResult<int>> ReorderAsync(int workspaceId, ReorderCategoriesRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync<int, int>(async context =>
        {
            if (request.Categories.Count == 0) return Reject<int>(CategoryWriteFailure.Invalid, "No categories to reorder");
            var ids = request.Categories.Select(entry => entry.CategoryId).ToList();
            if (ids.Distinct().Count() != ids.Count) return Reject<int>(CategoryWriteFailure.Invalid, "Duplicate category IDs are not allowed");
            if (request.Categories.Any(entry => entry.SortOrder < 0)) return Reject<int>(CategoryWriteFailure.Invalid, "Sort order cannot be negative");

            var categories = await context.Categories.Where(c => ids.Contains(c.Id) && c.WorkspaceId == workspaceId &&
                c.Collection!.WorkspaceId == workspaceId).ToDictionaryAsync(c => c.Id, cancellationToken);
            if (categories.Count != ids.Count) return Reject<int>(CategoryWriteFailure.Invalid, "One or more categories were not found in this workspace");
            if (categories.Values.Any(c => c.IsSystem)) return Reject<int>(CategoryWriteFailure.Forbidden, "System categories cannot be reordered.");
            var collectionIds = categories.Values.Select(c => c.CollectionId).Distinct().ToList();
            if (collectionIds.Count != 1) return Reject<int>(CategoryWriteFailure.Invalid, "All categories must belong to the same collection");

            foreach (var entry in request.Categories) categories[entry.CategoryId].SortOrder = entry.SortOrder;
            return CategoryWriteResult<int>.Success(collectionIds[0]);
        }, collectionId => collectionId, cancellationToken);

    public Task<CategoryWriteResult<bool>> DeleteAsync(int categoryId, int workspaceId, CancellationToken cancellationToken = default) =>
        ExecuteAsync<bool, bool>(async context =>
        {
            var category = await context.Categories.SingleOrDefaultAsync(c => c.Id == categoryId && c.WorkspaceId == workspaceId &&
                c.Collection!.WorkspaceId == workspaceId, cancellationToken);
            if (category is null) return Reject<bool>(CategoryWriteFailure.NotFound, "Category not found");
            if (category.IsSystem) return Reject<bool>(CategoryWriteFailure.Forbidden, "System categories cannot be deleted.");

            var children = await context.Categories.Where(c => c.ParentCategoryId == categoryId).ToListAsync(cancellationToken);
            var items = await context.Items.Where(item => item.CategoryId == categoryId).ToListAsync(cancellationToken);
            if (children.Any(child => child.WorkspaceId != workspaceId || child.CollectionId != category.CollectionId) ||
                items.Any(item => item.WorkspaceId != workspaceId || item.CollectionId != category.CollectionId))
                return Reject<bool>(CategoryWriteFailure.Conflict, "This category has inconsistent references and cannot be deleted.");

            var categories = await context.Categories.Where(c => c.WorkspaceId == workspaceId && c.CollectionId == category.CollectionId)
                .ToDictionaryAsync(c => c.Id, cancellationToken);
            var parentId = CategoryEditPolicy.IsValidParent(categoryId, category.ParentCategoryId, categories)
                ? category.ParentCategoryId : null;
            foreach (var child in children) child.ParentCategoryId = parentId;
            var unassigned = categories.Values.FirstOrDefault(c => c.IsSystem && c.Name == Constants.CategoryNames.UnassignedItems);
            foreach (var item in items) item.CategoryId = unassigned?.Id;
            context.Categories.Remove(category);
            return CategoryWriteResult<bool>.Success(true);
        }, deleted => deleted, cancellationToken);

    private static void ReplaceTemplates(AppDbContext context, Category category, List<int> templateIds)
    {
        var existing = category.CategoryItemTemplates.ToDictionary(link => link.ItemTemplateId);
        foreach (var link in existing.Values.Where(link => !templateIds.Contains(link.ItemTemplateId)))
        {
            context.CategoryItemTemplates.Remove(link);
            category.CategoryItemTemplates.Remove(link);
        }
        for (var index = 0; index < templateIds.Count; index++)
        {
            if (existing.TryGetValue(templateIds[index], out var link)) link.SortOrder = index;
            else category.CategoryItemTemplates.Add(new CategoryItemTemplate { ItemTemplateId = templateIds[index], SortOrder = index });
        }
    }

    private async Task<CategoryWriteResult<TResponse>> ExecuteAsync<TState, TResponse>(
        Func<AppDbContext, Task<CategoryWriteResult<TState>>> operation, Func<TState, TResponse> project, CancellationToken cancellationToken)
    {
        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            var result = await operation(context);
            if (result.Error != null) return CategoryWriteResult<TResponse>.Failure(result.Error);
            await context.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CategoryWriteResult<TResponse>.Success(project(result.Value!));
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return Reject<TResponse>(CategoryWriteFailure.Conflict, "Categories changed while saving. Reload and try again.");
        }
    }

    private static CategoryWriteResult<T> Reject<T>(CategoryWriteFailure kind, string message) =>
        CategoryWriteResult<T>.Failure(new(kind, message));
}
