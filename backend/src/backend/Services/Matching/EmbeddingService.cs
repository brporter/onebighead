using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OneBigHead.Server.Models;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Services.Matching;

public class EmbeddingService : IEmbeddingService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LlmSettings _settings;
    private readonly ILogger<EmbeddingService> _logger;

    public EmbeddingService(
        IHttpClientFactory httpClientFactory,
        IOptions<LlmSettings> settings,
        ILogger<EmbeddingService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task<float[]> GenerateEmbeddingAsync(Item item, CancellationToken ct = default)
    {
        var text = BuildItemText(item);
        var client = _httpClientFactory.CreateClient("AzureOpenAIEmbedding");

        var requestBody = new
        {
            input = text,
            model = _settings.EmbeddingDeploymentName
        };

        var requestUrl = $"{_settings.ResolvedEmbeddingEndpoint.TrimEnd('/')}/openai/deployments/{_settings.EmbeddingDeploymentName}/embeddings?api-version=2024-02-01";

        var content = new StringContent(
            JsonSerializer.Serialize(requestBody),
            Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync(requestUrl, content, ct);
        response.EnsureSuccessStatusCode();

        var responseBody = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(responseBody);
        var embeddingArray = doc.RootElement
            .GetProperty("data")[0]
            .GetProperty("embedding");

        var vector = new float[embeddingArray.GetArrayLength()];
        var index = 0;
        foreach (var element in embeddingArray.EnumerateArray())
        {
            vector[index++] = element.GetSingle();
        }

        return vector;
    }

    public string ComputeContentHash(Item item)
    {
        var text = BuildItemText(item);
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public double CosineSimilarity(float[] a, float[] b)
    {
        if (a.Length != b.Length || a.Length == 0)
            return 0.0;

        double dotProduct = 0;
        double normA = 0;
        double normB = 0;

        for (int i = 0; i < a.Length; i++)
        {
            dotProduct += a[i] * (double)b[i];
            normA += a[i] * (double)a[i];
            normB += b[i] * (double)b[i];
        }

        var denominator = Math.Sqrt(normA) * Math.Sqrt(normB);
        if (denominator == 0)
            return 0.0;

        return dotProduct / denominator;
    }

    private static string BuildItemText(Item item)
    {
        var sb = new StringBuilder();
        sb.Append(item.Name);

        if (!string.IsNullOrWhiteSpace(item.Summary))
        {
            sb.Append(' ');
            sb.Append(item.Summary);
        }

        if (!string.IsNullOrWhiteSpace(item.Description))
        {
            sb.Append(' ');
            sb.Append(item.Description);
        }

        foreach (var prop in item.Properties)
        {
            sb.Append(' ');
            sb.Append(prop.Name);
            sb.Append(": ");
            sb.Append(prop.Value);
        }

        return sb.ToString();
    }
}
