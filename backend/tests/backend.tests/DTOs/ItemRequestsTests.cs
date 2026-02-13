using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Tests.DTOs;

[Trait("Category", "Unit")]
public class ItemRequestsTests
{
    private readonly JsonSerializerOptions _jsonOptions;

    public ItemRequestsTests()
    {
        // Match the JSON options used in Program.cs
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };
    }

    [Fact]
    public void CreateItemRequest_DeserializesUserFlag_FromNumber()
    {
        // This is what the frontend sends - userFlag as a number
        var json = """
        {
            "name": "Test Item",
            "collectionId": 1,
            "categoryId": 1,
            "userFlag": 2
        }
        """;

        var request = JsonSerializer.Deserialize<CreateItemRequest>(json, _jsonOptions);

        Assert.NotNull(request);
        Assert.Equal("Test Item", request!.Name);
        Assert.Equal(UserFlag.Want, request.UserFlag);
    }

    [Fact]
    public void CreateItemRequest_DeserializesUserFlag_FromString()
    {
        // This is what would work with JsonStringEnumConverter
        var json = """
        {
            "name": "Test Item",
            "collectionId": 1,
            "userFlag": "Want"
        }
        """;

        var request = JsonSerializer.Deserialize<CreateItemRequest>(json, _jsonOptions);

        Assert.NotNull(request);
        Assert.Equal(UserFlag.Want, request!.UserFlag);
    }

    [Fact]
    public void UpdateItemRequest_DeserializesUserFlag_FromNumber()
    {
        var json = """
        {
            "name": "Test Item",
            "collectionId": 1,
            "userFlag": 3
        }
        """;

        var request = JsonSerializer.Deserialize<UpdateItemRequest>(json, _jsonOptions);

        Assert.NotNull(request);
        Assert.Equal(UserFlag.TradeOrSell, request!.UserFlag);
    }

    [Theory]
    [InlineData(0, UserFlag.None)]
    [InlineData(1, UserFlag.Have)]
    [InlineData(2, UserFlag.Want)]
    [InlineData(3, UserFlag.TradeOrSell)]
    public void CreateItemRequest_DeserializesAllUserFlagValues_FromNumber(int numericValue, UserFlag expected)
    {
        var json = $$$"""
        {
            "name": "Test Item",
            "collectionId": 1,
            "userFlag": {{{numericValue}}}
        }
        """;

        var request = JsonSerializer.Deserialize<CreateItemRequest>(json, _jsonOptions);

        Assert.NotNull(request);
        Assert.Equal(expected, request!.UserFlag);
    }

    [Fact]
    public void CreateItemRequest_ToItem_IncludesUserFlag()
    {
        var request = new CreateItemRequest
        {
            Name = "Test",
            CollectionId = 1,
            UserFlag = UserFlag.Want
        };

        var item = request.ToItem(workspaceId: 1);

        Assert.Equal(UserFlag.Want, item.UserFlag);
    }

    [Fact]
    public void UpdateItemRequest_ToItem_IncludesUserFlag()
    {
        var request = new UpdateItemRequest
        {
            Name = "Test",
            CollectionId = 1,
            UserFlag = UserFlag.TradeOrSell
        };

        var item = request.ToItem(id: 1, workspaceId: 1);

        Assert.Equal(UserFlag.TradeOrSell, item.UserFlag);
    }
}
