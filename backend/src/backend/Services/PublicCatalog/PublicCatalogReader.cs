using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.PublicCatalog;

public sealed class PublicCatalogReader(IDbContextFactory<AppDbContext> contexts, IVisibilityService visibility) : IPublicCatalogReader
{
    public Task<PublicWorkspaceDto?> GetWorkspaceAsync(string slug, CancellationToken cancellationToken) =>
        ReadAsync(slug, context => PublicWorkspaces(context, slug)
            .Select(workspace => new PublicWorkspaceDto { Name = workspace.Name, Slug = workspace.Slug! })
            .SingleOrDefaultAsync(cancellationToken), cancellationToken);

    public Task<List<PublicCollectionDto>?> GetCollectionsAsync(string slug, CancellationToken cancellationToken) =>
        ReadAsync<List<PublicCollectionDto>>(slug, async context =>
        {
            if (!await PublicWorkspaces(context, slug).AnyAsync(cancellationToken)) return null;
            var collections = await PublicCollections(context, slug).OrderBy(collection => collection.Name)
                .ThenBy(collection => collection.Id).ToListAsync(cancellationToken);
            return collections.Select(CollectionDto).ToList();
        }, cancellationToken);

    public Task<PublicCollectionDetailDto?> GetCollectionAsync(string slug, int collectionId, CancellationToken cancellationToken) =>
        ReadAsync<PublicCollectionDetailDto>(slug, async context =>
        {
            var collection = await PublicCollections(context, slug).SingleOrDefaultAsync(collection => collection.Id == collectionId, cancellationToken);
            if (collection is null) return null;
            var categories = await CategoriesAsync(context, collection, cancellationToken);
            var visibleCategories = categories.Where(category => category.EffectiveIsPublic).ToList();
            var categoryIds = visibleCategories.Select(category => category.Id).ToList();
            var associations = await context.CategoryItemTemplates.AsNoTracking()
                .Where(association => categoryIds.Contains(association.CategoryId) &&
                    (association.ItemTemplate!.WorkspaceId == null || association.ItemTemplate.WorkspaceId == collection.WorkspaceId))
                .OrderBy(association => association.SortOrder).ThenBy(association => association.ItemTemplateId)
                .Select(association => new { association.CategoryId, association.ItemTemplateId }).ToListAsync(cancellationToken);
            var templateIds = associations.ToLookup(association => association.CategoryId, association => association.ItemTemplateId);
            return new PublicCollectionDetailDto
            {
                Collection = CollectionDto(collection),
                Categories = visibleCategories.Select(category => new PublicCategoryDto
                {
                    Id = category.Id, Name = category.Name, ParentCategoryId = category.ParentCategoryId,
                    IsSystem = category.IsSystem, ItemTemplateIds = templateIds[category.Id].ToList()
                }).ToList()
            };
        }, cancellationToken);

    public Task<List<PublicItemSummaryDto>?> GetItemsAsync(string slug, int collectionId, int? categoryId, CancellationToken cancellationToken) =>
        ReadAsync<List<PublicItemSummaryDto>>(slug, async context =>
        {
            var collection = await PublicCollections(context, slug).SingleOrDefaultAsync(collection => collection.Id == collectionId, cancellationToken);
            if (collection is null) return null;
            var categories = await CategoriesAsync(context, collection, cancellationToken);
            var items = await context.Items.AsNoTracking()
                .Where(item => item.WorkspaceId == collection.WorkspaceId && item.CollectionId == collection.Id &&
                    item.Visibility == Visibility.Public && (categoryId == null || item.CategoryId == categoryId))
                .OrderBy(item => item.Name).ThenBy(item => item.Id)
                .Select(item => new Item
                {
                    Id = item.Id, WorkspaceId = item.WorkspaceId, CollectionId = item.CollectionId,
                    CategoryId = item.CategoryId, Visibility = item.Visibility, Name = item.Name,
                    Summary = item.Summary, Images = item.Images
                }).ToListAsync(cancellationToken);
            visibility.ComputeEffectiveVisibility(items, collection, categories);
            return items.Where(item => item.EffectiveIsPublic).Select(item => new PublicItemSummaryDto
            {
                Id = item.Id!.Value, Name = item.Name, Summary = item.Summary,
                PrimaryImageUrl = item.Images.FirstOrDefault()?.Url, CategoryId = item.CategoryId
            }).ToList();
        }, cancellationToken);

    public Task<PublicItemDto?> GetItemAsync(string slug, int itemId, CancellationToken cancellationToken) =>
        ReadAsync<PublicItemDto>(slug, async context =>
        {
            var row = await (from item in context.Items.AsNoTracking()
                join collection in PublicCollections(context, slug) on item.CollectionId equals collection.Id
                where item.Id == itemId && item.WorkspaceId == collection.WorkspaceId && item.Visibility == Visibility.Public
                select new { Item = item, Collection = collection }).SingleOrDefaultAsync(cancellationToken);
            if (row is null) return null;
            var categories = await CategoriesAsync(context, row.Collection, cancellationToken);
            var category = categories.FirstOrDefault(category => category.Id == row.Item.CategoryId);
            visibility.ComputeEffectiveVisibility(row.Item, row.Collection, category);
            if (!row.Item.EffectiveIsPublic) return null;
            return new PublicItemDto
            {
                Id = row.Item.Id!.Value, Name = row.Item.Name, Summary = row.Item.Summary, Description = row.Item.Description,
                Properties = row.Item.Properties.Select(property => new PublicItemPropertyDto
                    { Category = property.Category, Name = property.Name, Value = property.Value }).ToList(),
                Images = row.Item.Images.Select(image => new PublicItemImageDto { Url = image.Url, Alt = image.Alt }).ToList(),
                CategoryId = row.Item.CategoryId, CategoryName = category?.Name, TemplateKey = row.Item.TemplateKey
            };
        }, cancellationToken);

    private async Task<T?> ReadAsync<T>(string slug, Func<AppDbContext, Task<T?>> read, CancellationToken cancellationToken) where T : class
    {
        if (string.IsNullOrWhiteSpace(slug)) return null;
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        await using var snapshot = await context.Database.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
        return await read(context);
    }

    private static IQueryable<Workspace> PublicWorkspaces(AppDbContext context, string slug) =>
        context.Workspaces.AsNoTracking().Where(workspace => workspace.Slug == slug && !workspace.IsDeleted);

    private static IQueryable<Collection> PublicCollections(AppDbContext context, string slug) =>
        context.Collections.AsNoTracking().Where(collection => collection.Visibility == Visibility.Public &&
            collection.Workspace!.Slug == slug && !collection.Workspace.IsDeleted);

    private async Task<List<Category>> CategoriesAsync(AppDbContext context, Collection collection, CancellationToken cancellationToken)
    {
        var categories = await context.Categories.AsNoTracking()
            .Where(category => category.WorkspaceId == collection.WorkspaceId && category.CollectionId == collection.Id)
            .OrderBy(category => category.SortOrder).ThenBy(category => category.Name).ThenBy(category => category.Id)
            .ToListAsync(cancellationToken);
        visibility.ComputeEffectiveVisibility(categories, collection);
        return categories;
    }

    private static PublicCollectionDto CollectionDto(Collection collection) => new()
    {
        Id = collection.Id, Name = collection.Name, Description = collection.Description,
        HeroImageUrl = collection.HeroImageUrl, Slug = collection.Slug
    };
}
