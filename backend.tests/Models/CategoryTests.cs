using OneBigHead.Server.Models;
using System.Text.Json;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class CategoryTests
{
    [Fact]
    public void Category_DefaultValues_AreSetCorrectly()
    {
        // Act
        var category = new Category();

        // Assert
        Assert.Equal(0, category.Id);
        Assert.Equal(0, category.WorkspaceId);
        Assert.Equal(0, category.CollectionId);
        Assert.Equal(string.Empty, category.Name);
        Assert.Equal(string.Empty, category.Description);
        Assert.False(category.IsSystem);
        Assert.Null(category.ParentCategoryId);
        Assert.Null(category.ParentCategory);
        Assert.NotNull(category.ChildCategories);
        Assert.Empty(category.ChildCategories);
        Assert.Null(category.Workspace);
        Assert.Null(category.Collection);
    }

    [Fact]
    public void Category_PropertiesCanBeSet()
    {
        // Arrange
        var workspace = new Workspace { Id = 2, Name = "Test Workspace" };
        var collection = new Collection { Id = 4, Name = "Test Collection", Slug = "test" };
        var parent = new Category { Id = 3, Name = "Parent" };

        // Act
        var category = new Category
        {
            Id = 1,
            WorkspaceId = 2,
            CollectionId = 4,
            Name = "Test Name",
            Description = "Test Description",
            IsSystem = true,
            ParentCategoryId = 3,
            ParentCategory = parent,
            Workspace = workspace,
            Collection = collection
        };

        // Assert
        Assert.Equal(1, category.Id);
        Assert.Equal(2, category.WorkspaceId);
        Assert.Equal(4, category.CollectionId);
        Assert.Equal("Test Name", category.Name);
        Assert.Equal("Test Description", category.Description);
        Assert.True(category.IsSystem);
        Assert.Equal(3, category.ParentCategoryId);
        Assert.Same(parent, category.ParentCategory);
        Assert.Same(workspace, category.Workspace);
        Assert.Same(collection, category.Collection);
    }

    [Fact]
    public void Category_JsonSerialization_UsesCorrectPropertyName()
    {
        // Arrange
        var category = new Category { Id = 42, WorkspaceId = 1, Name = "Test", Description = "Desc" };

        // Act
        var json = JsonSerializer.Serialize(category);

        // Assert
        Assert.Contains("\"categoryId\":42", json);
        Assert.DoesNotContain("\"Id\"", json);
    }

    [Fact]
    public void Category_JsonSerialization_ExcludesNavigationProperties()
    {
        // Arrange
        var parent = new Category { Id = 1, WorkspaceId = 1, Name = "Parent", Description = "Parent Desc" };
        var child = new Category 
        { 
            Id = 2, 
            WorkspaceId = 1, 
            Name = "Child", 
            Description = "Child Desc",
            ParentCategoryId = 1,
            ParentCategory = parent
        };
        parent.ChildCategories.Add(child);

        // Act
        var json = JsonSerializer.Serialize(child);

        // Assert
        // ParentCategory navigation property should not appear as an object
        Assert.DoesNotContain("\"ParentCategory\":", json);
        Assert.DoesNotContain("\"ChildCategories\":", json);
        // ParentCategoryId should be included (it's a regular property)
        Assert.Contains("\"ParentCategoryId\":1", json);
    }

    [Fact]
    public void Category_ChildCategories_CanBeModified()
    {
        // Arrange
        var parent = new Category { Id = 1, WorkspaceId = 1, Name = "Parent", Description = "Parent Desc" };
        var child1 = new Category { Id = 2, WorkspaceId = 1, Name = "Child 1", Description = "Child Desc" };
        var child2 = new Category { Id = 3, WorkspaceId = 1, Name = "Child 2", Description = "Child Desc" };

        // Act
        parent.ChildCategories.Add(child1);
        parent.ChildCategories.Add(child2);

        // Assert
        Assert.Equal(2, parent.ChildCategories.Count);
        Assert.Contains(child1, parent.ChildCategories);
        Assert.Contains(child2, parent.ChildCategories);
    }
}

