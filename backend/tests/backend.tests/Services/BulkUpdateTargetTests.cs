using OneBigHead.Server.Models;
using OneBigHead.Server.Services.BulkUpdate;

namespace OneBigHead.Server.Tests.Services;

public class BulkUpdateTargetTests
{
    [Theory]
    [InlineData(null, null, null)]
    [InlineData("", null, null)]
    [InlineData("invalid", null, null)]
    [InlineData("0", 1, 1)]
    [InlineData("999", 1, 1)]
    [InlineData("template", null, null)]
    [InlineData("category", null, null)]
    [InlineData("category", 0, null)]
    [InlineData("category", -1, null)]
    [InlineData("collection", null, null)]
    [InlineData("collection", null, 0)]
    [InlineData("collection", null, -1)]
    public void MissingOrInvalidTargets_AreRejected(string? scope, int? category, int? collection)
        => Assert.False(BulkUpdateTarget.TryCreate(scope, null, category, collection, null, out _));

    [Fact]
    public void EmptyTemplateKey_IsRejected()
        => Assert.False(BulkUpdateTarget.TryCreate("template", Guid.Empty, null, null, null, out _));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void InvalidExcludedItem_IsRejected(int excluded)
        => Assert.False(BulkUpdateTarget.TryCreate("collection", null, null, 1, excluded, out _));

    [Theory]
    [InlineData("TEMPLATE", BulkUpdateScope.Template)]
    [InlineData("Category", BulkUpdateScope.Category)]
    [InlineData("collection", BulkUpdateScope.Collection)]
    public void ValidScope_IsCaseInsensitiveAndIgnoresUnrelatedTargetIds(string scope, BulkUpdateScope expected)
    {
        var template = Guid.NewGuid();
        Assert.True(BulkUpdateTarget.TryCreate(scope, template, 10, 20, 30, out var target));
        Assert.Equal(expected, target.Scope);
        Assert.Equal(expected == BulkUpdateScope.Template ? template : null, target.TemplateKey);
        Assert.Equal(expected == BulkUpdateScope.Category ? 10 : null, target.CategoryId);
        Assert.Equal(expected == BulkUpdateScope.Collection ? 20 : null, target.CollectionId);
        Assert.Equal(30, target.ExcludeItemId);
    }

    [Fact]
    public void InvalidInternalScope_CannotAccidentallySelectEveryItem()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new BulkUpdateTarget((BulkUpdateScope)999)
            .Select(Array.Empty<Item>().AsQueryable(), 1));
}
