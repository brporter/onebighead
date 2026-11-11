namespace OneBigHead.Server.Services.Images;

public interface IImageFormatDetector
{
    /// <summary>Detects an allowed content type from the bytes, or returns null.</summary>
    string? Detect(byte[] data);
}
