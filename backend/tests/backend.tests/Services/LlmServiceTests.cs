using System.Net;
using System.Text;
using System.Text.Json;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Matching;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class LlmServiceTests
{
    private readonly LlmSettings _settings;
    private readonly Mock<ILogger<LlmService>> _mockLogger;

    public LlmServiceTests()
    {
        _settings = new LlmSettings
        {
            Endpoint = "https://test.openai.azure.com",
            ApiKey = "test-key",
            DeploymentName = "gpt-4o-mini"
        };
        _mockLogger = new Mock<ILogger<LlmService>>();
    }

    private LlmService CreateService(HttpResponseMessage response)
    {
        var handler = new Mock<HttpMessageHandler>();
        handler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        var client = new HttpClient(handler.Object);
        var mockFactory = new Mock<IHttpClientFactory>();
        mockFactory.Setup(f => f.CreateClient("AzureOpenAI")).Returns(client);

        return new LlmService(mockFactory.Object, Options.Create(_settings), _mockLogger.Object);
    }

    [Fact]
    public async Task EvaluateMatchesAsync_EmptyCandidates_ReturnsEmpty()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        var service = CreateService(response);

        var item = new Item { Id = 1, Name = "Test", Properties = new(), Images = new() };
        var result = await service.EvaluateMatchesAsync(item, new List<Item>());

        Assert.Empty(result);
    }

    [Fact]
    public async Task EvaluateMatchesAsync_ValidResponse_ParsesMatches()
    {
        var llmContent = JsonSerializer.Serialize(new
        {
            matches = new[]
            {
                new { itemId = 10, confidence = 0.85, reason = "Same game" },
                new { itemId = 20, confidence = 0.5, reason = "Similar genre" }
            }
        });

        var apiResponse = JsonSerializer.Serialize(new
        {
            choices = new[]
            {
                new
                {
                    message = new { content = llmContent }
                }
            }
        });

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(apiResponse, Encoding.UTF8, "application/json")
        };

        var service = CreateService(response);

        var wantItem = new Item { Id = 1, Name = "Pokemon Red", Properties = new(), Images = new() };
        var candidates = new List<Item>
        {
            new() { Id = 10, Name = "Pokemon Red CIB", Properties = new(), Images = new() },
            new() { Id = 20, Name = "Pokemon Blue", Properties = new(), Images = new() }
        };

        var results = await service.EvaluateMatchesAsync(wantItem, candidates);

        Assert.Equal(2, results.Count);
        Assert.Equal(10, results[0].ItemId);
        Assert.Equal(0.85, results[0].ConfidenceScore);
        Assert.Equal("Same game", results[0].Reason);
        Assert.Equal(20, results[1].ItemId);
        Assert.Equal(0.5, results[1].ConfidenceScore);
    }

    [Fact]
    public async Task EvaluateMatchesAsync_MalformedResponse_ReturnsEmpty()
    {
        var apiResponse = JsonSerializer.Serialize(new
        {
            choices = new[]
            {
                new
                {
                    message = new { content = "not valid json" }
                }
            }
        });

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(apiResponse, Encoding.UTF8, "application/json")
        };

        var service = CreateService(response);
        var wantItem = new Item { Id = 1, Name = "Test", Properties = new(), Images = new() };
        var candidates = new List<Item>
        {
            new() { Id = 10, Name = "Trade", Properties = new(), Images = new() }
        };

        var results = await service.EvaluateMatchesAsync(wantItem, candidates);

        Assert.Empty(results);
    }

    [Fact]
    public async Task EvaluateMatchesAsync_HttpError_Throws()
    {
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var service = CreateService(response);

        var wantItem = new Item { Id = 1, Name = "Test", Properties = new(), Images = new() };
        var candidates = new List<Item>
        {
            new() { Id = 10, Name = "Trade", Properties = new(), Images = new() }
        };

        await Assert.ThrowsAsync<HttpRequestException>(
            () => service.EvaluateMatchesAsync(wantItem, candidates));
    }
}
