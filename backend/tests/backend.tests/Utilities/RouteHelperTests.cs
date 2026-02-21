using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Tests.Utilities;

[Trait("Category", "Unit")]
public class RouteHelperTests
{
    [Fact]
    public void IsMatch_MatchingRoute_ReturnsTrue()
    {
        // Arrange
        var helper = new RouteHelper();

        // Act
        var result = helper.IsMatch("/api/items/{id}", "/api/items/123");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsMatch_NonMatchingRoute_ReturnsFalse()
    {
        // Arrange
        var helper = new RouteHelper();

        // Act
        var result = helper.IsMatch("/api/items/{id}", "/api/users/123");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsMatch_ExactRoute_ReturnsTrue()
    {
        // Arrange
        var helper = new RouteHelper();

        // Act
        var result = helper.IsMatch("/api/health", "/api/health");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsMatch_CachedResult_ReturnsSameValue()
    {
        // Arrange
        var helper = new RouteHelper();
        var template = "/api/items/{id}";
        var path = "/api/items/123";

        // Act - call twice to exercise cache hit path
        var firstResult = helper.IsMatch(template, path);
        var secondResult = helper.IsMatch(template, path);

        // Assert
        Assert.True(firstResult);
        Assert.True(secondResult);
    }

    [Fact]
    public void IsMatch_CachedFalseResult_ReturnsFalse()
    {
        // Arrange
        var helper = new RouteHelper();
        var template = "/api/items/{id}";

        // Act - first call caches false, second call returns cached false
        var firstResult = helper.IsMatch(template, "/completely/different");
        var secondResult = helper.IsMatch(template, "/completely/different");

        // Assert
        Assert.False(firstResult);
        Assert.False(secondResult);
    }

    [Fact]
    public void IsMatch_MultipleTemplates_CachesIndependently()
    {
        // Arrange
        var helper = new RouteHelper();

        // Act
        var result1 = helper.IsMatch("/api/items/{id}", "/api/items/1");
        var result2 = helper.IsMatch("/api/users/{id}", "/api/users/42");

        // Assert
        Assert.True(result1);
        Assert.True(result2);
    }

    [Fact]
    public void IsMatch_MultipleSegmentParameters_ReturnsTrue()
    {
        // Arrange
        var helper = new RouteHelper();

        // Act
        var result = helper.IsMatch(
            "/api/collections/{collectionId}/items/{itemId}",
            "/api/collections/5/items/10");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsMatch_RootPath_ReturnsTrue()
    {
        // Arrange
        var helper = new RouteHelper();

        // Act
        var result = helper.IsMatch("/", "/");

        // Assert
        Assert.True(result);
    }
}
