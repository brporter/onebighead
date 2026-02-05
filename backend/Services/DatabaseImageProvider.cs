using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Services;

public class DatabaseImageProvider : IImageProvider
{
    private readonly AppDbContext _context;

    public DatabaseImageProvider(AppDbContext context)
    {
        _context = context;
    }

    public async Task<StoredImageInfo> StoreAsync(int workspaceId, string fileName, string contentType, Stream data)
    {
        using var memoryStream = new MemoryStream();
        await data.CopyToAsync(memoryStream);
        var imageData = memoryStream.ToArray();

        var image = new StoredImage
        {
            Id = Guid.NewGuid(),
            WorkspaceId = workspaceId,
            FileName = fileName,
            ContentType = contentType,
            Data = imageData,
            CreatedAt = DateTime.UtcNow
        };

        _context.StoredImages.Add(image);
        await _context.SaveChangesAsync();

        var url = $"/api/images/{image.Id}";
        return new StoredImageInfo(image.Id, url);
    }

    public async Task<RetrievedImage?> RetrieveAsync(Guid key, int workspaceId)
    {
        var image = await _context.StoredImages
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == key && i.WorkspaceId == workspaceId);

        if (image == null)
            return null;

        return new RetrievedImage(image.Data, image.ContentType, image.FileName);
    }

    public async Task DeleteAsync(Guid key, int workspaceId)
    {
        var image = await _context.StoredImages
            .FirstOrDefaultAsync(i => i.Id == key && i.WorkspaceId == workspaceId);
        
        if (image != null)
        {
            _context.StoredImages.Remove(image);
            await _context.SaveChangesAsync();
        }
    }
}
