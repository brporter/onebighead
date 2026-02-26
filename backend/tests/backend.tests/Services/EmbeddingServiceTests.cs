using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Matching;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class EmbeddingServiceTests
{
    private readonly EmbeddingService _service;
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;

    public EmbeddingServiceTests()
    {
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        var settings = Options.Create(new LlmSettings
        {
            Endpoint = "https://test.openai.azure.com",
            ApiKey = "test-key",
            EmbeddingDeploymentName = "text-embedding-3-small"
        });
        var logger = new Mock<ILogger<EmbeddingService>>();
        _service = new EmbeddingService(_mockHttpClientFactory.Object, settings, logger.Object);
    }

    [Fact]
    public void ComputeContentHash_ReturnsConsistentHash()
    {
        var item = CreateTestItem("Pokemon Red", "Game Boy game", "A classic RPG");
        var hash1 = _service.ComputeContentHash(item);
        var hash2 = _service.ComputeContentHash(item);

        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length); // SHA256 hex string
    }

    [Fact]
    public void ComputeContentHash_DifferentContent_DifferentHash()
    {
        var item1 = CreateTestItem("Pokemon Red", "Game Boy game", "A classic RPG");
        var item2 = CreateTestItem("Pokemon Blue", "Game Boy game", "A classic RPG");

        var hash1 = _service.ComputeContentHash(item1);
        var hash2 = _service.ComputeContentHash(item2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeContentHash_IncludesProperties()
    {
        var item1 = CreateTestItem("Pokemon Red", "", "");
        var item2 = CreateTestItem("Pokemon Red", "", "");
        item2.Properties.Add(new ItemProperty("General", "Condition", "Mint"));

        var hash1 = _service.ComputeContentHash(item1);
        var hash2 = _service.ComputeContentHash(item2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void CosineSimilarity_IdenticalVectors_ReturnsOne()
    {
        var vector = new float[] { 1.0f, 2.0f, 3.0f };
        var similarity = _service.CosineSimilarity(vector, vector);

        Assert.Equal(1.0, similarity, 6);
    }

    [Fact]
    public void CosineSimilarity_OrthogonalVectors_ReturnsZero()
    {
        var a = new float[] { 1.0f, 0.0f, 0.0f };
        var b = new float[] { 0.0f, 1.0f, 0.0f };
        var similarity = _service.CosineSimilarity(a, b);

        Assert.Equal(0.0, similarity, 6);
    }

    [Fact]
    public void CosineSimilarity_OppositeVectors_ReturnsNegativeOne()
    {
        var a = new float[] { 1.0f, 0.0f, 0.0f };
        var b = new float[] { -1.0f, 0.0f, 0.0f };
        var similarity = _service.CosineSimilarity(a, b);

        Assert.Equal(-1.0, similarity, 6);
    }

    [Fact]
    public void CosineSimilarity_EmptyVectors_ReturnsZero()
    {
        var similarity = _service.CosineSimilarity(Array.Empty<float>(), Array.Empty<float>());
        Assert.Equal(0.0, similarity);
    }

    [Fact]
    public void CosineSimilarity_DifferentLengths_ReturnsZero()
    {
        var a = new float[] { 1.0f, 2.0f };
        var b = new float[] { 1.0f, 2.0f, 3.0f };
        var similarity = _service.CosineSimilarity(a, b);

        Assert.Equal(0.0, similarity);
    }

    [Fact]
    public void CosineSimilarity_ZeroVector_ReturnsZero()
    {
        var a = new float[] { 0.0f, 0.0f, 0.0f };
        var b = new float[] { 1.0f, 2.0f, 3.0f };
        var similarity = _service.CosineSimilarity(a, b);

        Assert.Equal(0.0, similarity);
    }

    [Fact]
    public void CosineSimilarity_SimilarVectors_ReturnsHighValue()
    {
        var a = new float[] { 1.0f, 2.0f, 3.0f };
        var b = new float[] { 1.1f, 2.1f, 3.1f };
        var similarity = _service.CosineSimilarity(a, b);

        Assert.True(similarity > 0.99);
    }

    private static Item CreateTestItem(string name, string summary, string description)
    {
        return new Item
        {
            Id = 1,
            WorkspaceId = 1,
            CollectionId = 1,
            Name = name,
            Summary = summary,
            Description = description,
            Properties = new List<ItemProperty>()
        };
    }
}
