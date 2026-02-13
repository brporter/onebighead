namespace OneBigHead.Server.Services;

public interface IImageProcessor
{
    (byte[] Data, string ContentType) ResizeIfNeeded(byte[] imageData, string contentType);
}
