using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services;

public class DatabaseImageProvider : IImageProvider
{
    private readonly AppDbContext _context;

    public DatabaseImageProvider(AppDbContext context)
    {
        _context = context;
    }

    public async Task<StoredImageInfo> StoreAsync(int tenantId, string fileName, string contentType, Stream data)
    {
        using var memoryStream = new MemoryStream();
        await data.CopyToAsync(memoryStream);
        var imageData = memoryStream.ToArray();

        var image = new StoredImage
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
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

    public async Task<RetrievedImage?> RetrieveAsync(Guid key)
    {
        var image = await _context.StoredImages
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == key);

        if (image == null)
            return null;

        var stream = new MemoryStream(image.Data);
        return new RetrievedImage(stream, image.ContentType, image.FileName);
    }

    public async Task DeleteAsync(Guid key)
    {
        var image = await _context.StoredImages.FindAsync(key);
        if (image != null)
        {
            _context.StoredImages.Remove(image);
            await _context.SaveChangesAsync();
        }
    }
}
