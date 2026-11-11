namespace OneBigHead.Server.Services.Images;

public enum RasterImageFormat { Jpeg, Png, Webp }

public interface IRasterImageCodec
{
    /// <summary>Returns owned, decoded pixels, or null for unreadable data. The caller disposes the image.</summary>
    IDecodedRasterImage? Decode(byte[] data);
}

public interface IDecodedRasterImage : IDisposable
{
    int Width { get; }
    int Height { get; }

    /// <summary>Returns encoded pixels at the requested size, or null if resizing fails.</summary>
    byte[]? ResizeAndEncode(int width, int height, RasterImageFormat format);
}
