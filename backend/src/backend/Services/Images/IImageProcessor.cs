namespace OneBigHead.Server.Services.Images;

public interface IImageProcessor
{
    (byte[] Data, string ContentType) ResizeIfNeeded(byte[] imageData, string contentType);
}
