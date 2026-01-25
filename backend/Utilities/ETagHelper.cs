using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace backend.Utilities;

/// <summary>
/// Provides utilities for computing ETags for HTTP caching.
/// </summary>
public static class ETagHelper
{
    /// <summary>
    /// Computes an ETag for a collection of items by serializing them to JSON and hashing.
    /// </summary>
    /// <typeparam name="T">The type of items in the collection.</typeparam>
    /// <typeparam name="TKey">The type of the key used for ordering.</typeparam>
    /// <param name="items">The items to compute an ETag for.</param>
    /// <param name="orderByKey">A function to extract the key for ordering items before hashing.</param>
    /// <returns>A quoted ETag string suitable for HTTP headers.</returns>
    public static string ComputeETag<T, TKey>(IEnumerable<T> items, Func<T, TKey> orderByKey)
    {
        var json = JsonSerializer.Serialize(items.OrderBy(orderByKey));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return $"\"{Convert.ToBase64String(hash)}\"";
    }

    /// <summary>
    /// Computes an ETag for a single object by serializing it to JSON and hashing.
    /// </summary>
    /// <typeparam name="T">The type of the object.</typeparam>
    /// <param name="item">The item to compute an ETag for.</param>
    /// <returns>A quoted ETag string suitable for HTTP headers.</returns>
    public static string ComputeETag<T>(T item)
    {
        var json = JsonSerializer.Serialize(item);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return $"\"{Convert.ToBase64String(hash)}\"";
    }
}
