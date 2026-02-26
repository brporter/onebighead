using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ItemEmbeddingRepository : IItemEmbeddingRepository
{
    private readonly AppDbContext _context;

    public ItemEmbeddingRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<ItemEmbedding?> GetByItemIdAsync(int itemId)
    {
        return await _context.ItemEmbeddings
            .AsNoTracking()
            .FirstOrDefaultAsync(e => e.ItemId == itemId);
    }

    public async Task<List<ItemEmbedding>> GetAllForTradeOrSellAsync(int excludeWorkspaceId)
    {
        // Get all embeddings for TradeOrSell items from other workspaces.
        // We join with Items to filter by UserFlag; effective public visibility
        // is checked at the service layer since it depends on collection/category hierarchy.
        return await _context.ItemEmbeddings
            .AsNoTracking()
            .Where(e => e.WorkspaceId != excludeWorkspaceId)
            .Join(
                _context.Items.AsNoTracking().Where(i => i.UserFlag == UserFlag.TradeOrSell),
                e => e.ItemId,
                i => i.Id,
                (e, i) => e)
            .ToListAsync();
    }

    public async Task<ItemEmbedding> UpsertAsync(ItemEmbedding embedding)
    {
        var existing = await _context.ItemEmbeddings
            .FirstOrDefaultAsync(e => e.ItemId == embedding.ItemId);

        if (existing != null)
        {
            existing.Vector = embedding.Vector;
            existing.ContentHash = embedding.ContentHash;
            existing.WorkspaceId = embedding.WorkspaceId;
            existing.CreatedAt = DateTime.UtcNow;
        }
        else
        {
            embedding.CreatedAt = DateTime.UtcNow;
            _context.ItemEmbeddings.Add(embedding);
        }

        await _context.SaveChangesAsync();
        return existing ?? embedding;
    }

    public async Task DeleteByItemIdAsync(int itemId)
    {
        var embedding = await _context.ItemEmbeddings
            .FirstOrDefaultAsync(e => e.ItemId == itemId);

        if (embedding != null)
        {
            _context.ItemEmbeddings.Remove(embedding);
            await _context.SaveChangesAsync();
        }
    }
}
