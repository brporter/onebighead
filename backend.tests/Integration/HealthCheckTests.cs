using System.Net;
using System.Text.Json;

namespace backend.Tests.Integration;

[Trait("Category", "Integration")]
public class HealthCheckTests : IntegrationTestBase
{
    public HealthCheckTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    [Fact]
    public async Task HealthCheck_ReturnsHealthyStatus()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/health");

        // Assert
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var healthResponse = JsonSerializer.Deserialize<HealthResponse>(content, JsonOptions);
        Assert.NotNull(healthResponse);
        Assert.Equal("healthy", healthResponse.Status);
        Assert.True(healthResponse.Timestamp > DateTime.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public async Task HealthCheck_Authenticated_AlsoWorks()
    {
        // Act
        var response = await Client.GetAsync("/health");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    private class HealthResponse
    {
        public string Status { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}
