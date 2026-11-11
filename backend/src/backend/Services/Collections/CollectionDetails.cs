using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Collections;

public sealed class CollectionDetails(IDbContextFactory<AppDbContext> contexts) : ICollectionDetails
{
    public async Task<CollectionWriteResult> UpdateAsync(int userId, int workspaceId, int collectionId,
        UpdateCollectionRequest request, CancellationToken cancellationToken)
    {
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            var collection = await CollectionWriteAccess.ForMember(context, userId, workspaceId)
                .SingleOrDefaultAsync(collection => collection.Id == collectionId, cancellationToken);
            if (collection is null) return new(CollectionWriteStatus.NotFound);
            if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
                return new(CollectionWriteStatus.Invalid, Error: "Enter a name of 1–200 characters and valid collection details.");

            var name = request.Name.Trim();
            if (collection.Name != name)
                collection.Slug = await CollectionSlugs.CreateAsync(context, workspaceId, name, collectionId, cancellationToken);
            collection.Name = name;
            collection.Description = request.Description ?? string.Empty;
            collection.HeroImageUrl = request.HeroImageUrl;
            // Publication owns visibility. Track only changes to editable metadata.
            await context.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(CollectionWriteStatus.Success, collection);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception) ||
            exception.GetBaseException() is PostgresException
                { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_Collections_WorkspaceId_Slug" })
        {
            return CollectionWriteResult.ConcurrentChange();
        }
    }
}
