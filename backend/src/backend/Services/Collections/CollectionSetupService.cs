using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Collections;

public sealed class CollectionSetupService(
    IDbContextFactory<AppDbContext> contextFactory,
    IWorkspaceStatisticsWriter statistics) : ICollectionSetupService
{
    public async Task<Collection> CreateAsync(Collection collection, CollectionTheme? theme)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync();
        await CollectionSetupWrite.SaveAsync(context, collection, theme, statistics);
        await transaction.CommitAsync();
        return collection;
    }
}
