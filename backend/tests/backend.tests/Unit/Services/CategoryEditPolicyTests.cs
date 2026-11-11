using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class CategoryEditPolicyTests
{
    [Theory]
    [InlineData("")]
    [InlineData("  \t")]
    [InlineData("Unassigned Items")]
    [InlineData("  unASSIGNED items  ")]
    public void InvalidNames_AreRejected(string name) => Assert.NotNull(CategoryEditPolicy.ValidateFields(name, null));

    [Fact]
    public void FieldLimits_AllowExactLimits_AndRejectLongerValues()
    {
        Assert.Null(CategoryEditPolicy.ValidateFields(new string('N', 200), new string('D', 1000)));
        Assert.Null(CategoryEditPolicy.ValidateFields(" Name ", null));
        Assert.NotNull(CategoryEditPolicy.ValidateFields(new string('N', 201), null));
        Assert.NotNull(CategoryEditPolicy.ValidateFields("Name", new string('D', 1001)));
    }

    [Theory]
    [InlineData(null, null, true)]
    [InlineData(null, 1, true)]
    [InlineData(2, 1, true)]
    [InlineData(1, 1, false)]
    [InlineData(1, 3, false)]
    [InlineData(null, 4, false)]
    [InlineData(null, 5, false)]
    [InlineData(null, 6, false)]
    [InlineData(null, 8, false)]
    [InlineData(null, 99, false)]
    public void ParentPolicy_RejectsSelfDescendantsSystemAndIncompleteAncestry(int? categoryId, int? parentId, bool expected)
    {
        Category[] categories = [new() { Id = 1 }, new() { Id = 2, ParentCategoryId = 1 },
            new() { Id = 3, ParentCategoryId = 2 }, new() { Id = 4, IsSystem = true },
            new() { Id = 5, ParentCategoryId = 99 }, new() { Id = 6, ParentCategoryId = 7 },
            new() { Id = 7, ParentCategoryId = 6 }, new() { Id = 8, ParentCategoryId = 4 }];
        Assert.Equal(expected, CategoryEditPolicy.IsValidParent(categoryId, parentId, categories.ToDictionary(category => category.Id)));
    }
}
