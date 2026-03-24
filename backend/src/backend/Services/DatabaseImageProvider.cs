using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Services;

public class DatabaseImageProvider : IImageProvider
{
    private readonly AppDbContext _context;
    private readonly IWorkspaceStatisticsRepository _statsRepository;

    public DatabaseImageProvider(AppDbContext context, IWorkspaceStatisticsRepository statsRepository)
    {
        _context = context;
        _statsRepository = statsRepository;
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

        await _statsRepository.IncrementAsync(workspaceId, StatisticType.ImageCount);
        await _statsRepository.IncrementAsync(workspaceId, StatisticType.TotalImageSizeBytes, imageData.Length);

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

    public async Task<RetrievedImage?> RetrievePublicAsync(Guid key)
    {
        var image = await _context.StoredImages
            .AsNoTracking()
            .Include(i => i.Workspace)
            .FirstOrDefaultAsync(i => i.Id == key && i.Workspace != null && i.Workspace.Slug != null);

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
            var imageSize = image.Data.Length;
            _context.StoredImages.Remove(image);
            await _context.SaveChangesAsync();

            await _statsRepository.DecrementAsync(workspaceId, StatisticType.ImageCount);
            await _statsRepository.DecrementAsync(workspaceId, StatisticType.TotalImageSizeBytes, imageSize);
        }
    }
}
