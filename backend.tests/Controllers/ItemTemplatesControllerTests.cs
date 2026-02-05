using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class ItemTemplatesControllerTests
{
    private readonly Mock<IItemTemplateRepository> _mockTemplateRepository;
    private readonly ItemTemplatesController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public ItemTemplatesControllerTests()
    {
        _mockTemplateRepository = new Mock<IItemTemplateRepository>();
        _controller = new ItemTemplatesController(_mockTemplateRepository.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new("sub", TestUserId.ToString()),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region GetTemplates Tests

    [Fact]
    public async Task GetTemplates_ReturnsOkResult_WithAllAccessibleTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, WorkspaceId = null, Name = "System Template", Description = "System", Properties = new List<ItemTemplateProperty>() },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Workspace Template", Description = "Workspace", Properties = new List<ItemTemplateProperty>() }
        };
        _mockTemplateRepository.Setup(repo => repo.GetAllAccessibleAsync(TestWorkspaceId))
            .ReturnsAsync(templates);

        // Act
        var result = await _controller.GetTemplates();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplates = Assert.IsAssignableFrom<IEnumerable<ItemTemplateResponse>>(okResult.Value);
        Assert.Equal(2, returnedTemplates.Count());
    }

    [Fact]
    public async Task GetTemplates_ReturnsOkResult_WithEmptyList_WhenNoTemplates()
    {
        // Arrange
        _mockTemplateRepository.Setup(repo => repo.GetAllAccessibleAsync(TestWorkspaceId))
            .ReturnsAsync(new List<ItemTemplate>());

        // Act
        var result = await _controller.GetTemplates();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplates = Assert.IsAssignableFrom<IEnumerable<ItemTemplateResponse>>(okResult.Value);
        Assert.Empty(returnedTemplates);
    }

    [Fact]
    public async Task GetTemplates_WithSystemFilter_ReturnsOnlySystemTemplates()
    {
        // Arrange
        var systemTemplates = new List<ItemTemplate>
        {
            new() { Id = 1, WorkspaceId = null, Name = "System Template 1", Description = "System", Properties = new List<ItemTemplateProperty>() },
            new() { Id = 2, WorkspaceId = null, Name = "System Template 2", Description = "System", Properties = new List<ItemTemplateProperty>() }
        };
        _mockTemplateRepository.Setup(repo => repo.GetSystemTemplatesAsync(TestWorkspaceId))
            .ReturnsAsync(systemTemplates);

        // Act
        var result = await _controller.GetTemplates(filter: "system");

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplates = Assert.IsAssignableFrom<IEnumerable<ItemTemplateResponse>>(okResult.Value);
        Assert.Equal(2, returnedTemplates.Count());
        Assert.All(returnedTemplates, t => Assert.True(t.IsSystem));
        _mockTemplateRepository.Verify(repo => repo.GetSystemTemplatesAsync(TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task GetTemplates_WithWorkspaceFilter_ReturnsOnlyWorkspaceTemplates()
    {
        // Arrange
        var workspaceTemplates = new List<ItemTemplate>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Workspace Template 1", Description = "Workspace", Properties = new List<ItemTemplateProperty>() },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Workspace Template 2", Description = "Workspace", Properties = new List<ItemTemplateProperty>() }
        };
        _mockTemplateRepository.Setup(repo => repo.GetWorkspaceTemplatesAsync(TestWorkspaceId))
            .ReturnsAsync(workspaceTemplates);

        // Act
        var result = await _controller.GetTemplates(filter: "workspace");

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplates = Assert.IsAssignableFrom<IEnumerable<ItemTemplateResponse>>(okResult.Value);
        Assert.Equal(2, returnedTemplates.Count());
        Assert.All(returnedTemplates, t => Assert.False(t.IsSystem));
        _mockTemplateRepository.Verify(repo => repo.GetWorkspaceTemplatesAsync(TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task GetTemplates_WithAllFilter_ReturnsAllAccessibleTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, WorkspaceId = null, Name = "System Template", Description = "System", Properties = new List<ItemTemplateProperty>() },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Workspace Template", Description = "Workspace", Properties = new List<ItemTemplateProperty>() }
        };
        _mockTemplateRepository.Setup(repo => repo.GetAllAccessibleAsync(TestWorkspaceId))
            .ReturnsAsync(templates);

        // Act
        var result = await _controller.GetTemplates(filter: "all");

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplates = Assert.IsAssignableFrom<IEnumerable<ItemTemplateResponse>>(okResult.Value);
        Assert.Equal(2, returnedTemplates.Count());
        _mockTemplateRepository.Verify(repo => repo.GetAllAccessibleAsync(TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task GetTemplates_WithUnknownFilter_ReturnsAllAccessibleTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, WorkspaceId = null, Name = "System Template", Description = "System", Properties = new List<ItemTemplateProperty>() }
        };
        _mockTemplateRepository.Setup(repo => repo.GetAllAccessibleAsync(TestWorkspaceId))
            .ReturnsAsync(templates);

        // Act
        var result = await _controller.GetTemplates(filter: "invalid");

        // Assert
        Assert.IsType<OkObjectResult>(result.Result);
        _mockTemplateRepository.Verify(repo => repo.GetAllAccessibleAsync(TestWorkspaceId), Times.Once);
    }

    #endregion

    #region GetTemplate Tests

    [Fact]
    public async Task GetTemplate_ReturnsOkResult_WhenTemplateExists()
    {
        // Arrange
        var template = new ItemTemplate 
        { 
            Id = 1, 
            WorkspaceId = TestWorkspaceId, 
            Name = "Test Template", 
            Description = "Test Description",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, Category = "Details", Name = "Color", SortOrder = 0 }
            }
        };
        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(template);

        // Act
        var result = await _controller.GetTemplate(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplate = Assert.IsType<ItemTemplateResponse>(okResult.Value);
        Assert.Equal("Test Template", returnedTemplate.Name);
        Assert.Equal("Test Description", returnedTemplate.Description);
        Assert.Single(returnedTemplate.Properties);
    }

    [Fact]
    public async Task GetTemplate_ReturnsNotFound_WhenTemplateDoesNotExist()
    {
        // Arrange
        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((ItemTemplate?)null);

        // Act
        var result = await _controller.GetTemplate(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task GetTemplate_ReturnsSystemTemplate_WhenAccessible()
    {
        // Arrange
        var template = new ItemTemplate 
        { 
            Id = 1, 
            WorkspaceId = null, // System template
            Name = "System Template", 
            Description = "System Description",
            Properties = new List<ItemTemplateProperty>()
        };
        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(template);

        // Act
        var result = await _controller.GetTemplate(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplate = Assert.IsType<ItemTemplateResponse>(okResult.Value);
        Assert.True(returnedTemplate.IsSystem);
    }

    #endregion

    #region CreateTemplate Tests

    [Fact]
    public async Task CreateTemplate_ReturnsCreatedAtAction_WithNewTemplate()
    {
        // Arrange
        var request = new CreateItemTemplateRequest
        {
            Name = "New Template",
            Description = "New Description",
            Properties = new List<ItemTemplatePropertyDto>
            {
                new() { Category = "Details", Name = "Brand" },
                new() { Category = "Details", Name = "Model" }
            }
        };
        var createdTemplate = new ItemTemplate
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "New Template",
            Description = "New Description",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, Category = "Details", Name = "Brand", SortOrder = 0 },
                new() { Id = 2, Category = "Details", Name = "Model", SortOrder = 1 }
            }
        };

        _mockTemplateRepository.Setup(repo => repo.CreateAsync(It.IsAny<ItemTemplate>()))
            .ReturnsAsync(createdTemplate);

        // Act
        var result = await _controller.CreateTemplate(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(nameof(_controller.GetTemplate), createdResult.ActionName);
        var returnedTemplate = Assert.IsType<ItemTemplateResponse>(createdResult.Value);
        Assert.Equal("New Template", returnedTemplate.Name);
        Assert.Equal(2, returnedTemplate.Properties.Count);
    }

    [Fact]
    public async Task CreateTemplate_SetsWorkspaceId_FromClaims()
    {
        // Arrange
        var request = new CreateItemTemplateRequest
        {
            Name = "Workspace Template",
            Description = "Description",
            Properties = new List<ItemTemplatePropertyDto>()
        };
        var createdTemplate = new ItemTemplate
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "Workspace Template",
            Description = "Description",
            Properties = new List<ItemTemplateProperty>()
        };

        _mockTemplateRepository.Setup(repo => repo.CreateAsync(It.IsAny<ItemTemplate>()))
            .ReturnsAsync(createdTemplate);

        // Act
        await _controller.CreateTemplate(request);

        // Assert
        _mockTemplateRepository.Verify(repo => repo.CreateAsync(
            It.Is<ItemTemplate>(t => t.WorkspaceId == TestWorkspaceId)), Times.Once);
    }

    [Fact]
    public async Task CreateTemplate_ReturnsCreatedTemplate_WithCorrectId()
    {
        // Arrange
        var request = new CreateItemTemplateRequest
        {
            Name = "New Template",
            Description = "Description",
            Properties = new List<ItemTemplatePropertyDto>()
        };
        var createdTemplate = new ItemTemplate
        {
            Id = 42,
            WorkspaceId = TestWorkspaceId,
            Name = "New Template",
            Description = "Description",
            Properties = new List<ItemTemplateProperty>()
        };

        _mockTemplateRepository.Setup(repo => repo.CreateAsync(It.IsAny<ItemTemplate>()))
            .ReturnsAsync(createdTemplate);

        // Act
        var result = await _controller.CreateTemplate(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(42, createdResult.RouteValues?["id"]);
    }

    #endregion

    #region UpdateTemplate Tests

    [Fact]
    public async Task UpdateTemplate_ReturnsOkResult_WhenWorkspaceTemplateUpdated()
    {
        // Arrange
        var request = new UpdateItemTemplateRequest
        {
            Name = "Updated Template",
            Description = "Updated Description",
            Properties = new List<ItemTemplatePropertyDto>
            {
                new() { Category = "Details", Name = "Updated Property" }
            }
        };
        var existingTemplate = new ItemTemplate 
        { 
            Id = 1, 
            WorkspaceId = TestWorkspaceId, 
            Name = "Original Template",
            Properties = new List<ItemTemplateProperty>()
        };
        var updatedTemplate = new ItemTemplate
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "Updated Template",
            Description = "Updated Description",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, Category = "Details", Name = "Updated Property", SortOrder = 0 }
            }
        };

        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingTemplate);
        _mockTemplateRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<ItemTemplate>(), TestWorkspaceId))
            .ReturnsAsync(updatedTemplate);

        // Act
        var result = await _controller.UpdateTemplate(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplate = Assert.IsType<ItemTemplateResponse>(okResult.Value);
        Assert.Equal("Updated Template", returnedTemplate.Name);
        Assert.Equal("Updated Description", returnedTemplate.Description);
    }

    [Fact]
    public async Task UpdateTemplate_ReturnsNotFound_WhenTemplateDoesNotExist()
    {
        // Arrange
        var request = new UpdateItemTemplateRequest
        {
            Name = "Updated Template",
            Description = "Description",
            Properties = new List<ItemTemplatePropertyDto>()
        };
        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((ItemTemplate?)null);

        // Act
        var result = await _controller.UpdateTemplate(999, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task UpdateTemplate_CopiesSystemTemplate_WhenEditingSystemTemplate()
    {
        // Arrange
        var request = new UpdateItemTemplateRequest
        {
            Name = "My Custom Template",
            Description = "Customized",
            Properties = new List<ItemTemplatePropertyDto>
            {
                new() { Category = "Custom", Name = "Custom Property" }
            }
        };
        var systemTemplate = new ItemTemplate 
        { 
            Id = 1, 
            WorkspaceId = null, // System template
            Name = "System Template",
            Properties = new List<ItemTemplateProperty>()
        };
        var copiedTemplate = new ItemTemplate
        {
            Id = 100, // New ID for the copied template
            WorkspaceId = TestWorkspaceId,
            Name = "My Custom Template",
            Description = "Customized",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, Category = "Custom", Name = "Custom Property", SortOrder = 0 }
            }
        };

        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(systemTemplate);
        _mockTemplateRepository.Setup(repo => repo.CopySystemTemplateAsync(1, TestWorkspaceId, It.IsAny<ItemTemplate>()))
            .ReturnsAsync(copiedTemplate);

        // Act
        var result = await _controller.UpdateTemplate(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTemplate = Assert.IsType<ItemTemplateResponse>(okResult.Value);
        Assert.Equal("My Custom Template", returnedTemplate.Name);
        Assert.Equal(100, returnedTemplate.ItemTemplateId);
        Assert.False(returnedTemplate.IsSystem);
        _mockTemplateRepository.Verify(repo => repo.CopySystemTemplateAsync(1, TestWorkspaceId, It.IsAny<ItemTemplate>()), Times.Once);
        _mockTemplateRepository.Verify(repo => repo.UpdateAsync(It.IsAny<int>(), It.IsAny<ItemTemplate>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task UpdateTemplate_DoesNotCopy_WhenEditingWorkspaceTemplate()
    {
        // Arrange
        var request = new UpdateItemTemplateRequest
        {
            Name = "Updated Workspace Template",
            Description = "Updated",
            Properties = new List<ItemTemplatePropertyDto>()
        };
        var workspaceTemplate = new ItemTemplate 
        { 
            Id = 1, 
            WorkspaceId = TestWorkspaceId, // Workspace-owned template
            Name = "Workspace Template",
            Properties = new List<ItemTemplateProperty>()
        };
        var updatedTemplate = new ItemTemplate
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "Updated Workspace Template",
            Description = "Updated",
            Properties = new List<ItemTemplateProperty>()
        };

        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(workspaceTemplate);
        _mockTemplateRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<ItemTemplate>(), TestWorkspaceId))
            .ReturnsAsync(updatedTemplate);

        // Act
        await _controller.UpdateTemplate(1, request);

        // Assert
        _mockTemplateRepository.Verify(repo => repo.UpdateAsync(1, It.IsAny<ItemTemplate>(), TestWorkspaceId), Times.Once);
        _mockTemplateRepository.Verify(repo => repo.CopySystemTemplateAsync(It.IsAny<int>(), It.IsAny<int>(), It.IsAny<ItemTemplate>()), Times.Never);
    }

    [Fact]
    public async Task UpdateTemplate_ReturnsNotFound_WhenUpdateReturnsNull()
    {
        // Arrange
        var request = new UpdateItemTemplateRequest
        {
            Name = "Updated Template",
            Description = "Updated",
            Properties = new List<ItemTemplatePropertyDto>()
        };
        var existingTemplate = new ItemTemplate 
        { 
            Id = 1, 
            WorkspaceId = TestWorkspaceId,
            Name = "Template",
            Properties = new List<ItemTemplateProperty>()
        };

        _mockTemplateRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingTemplate);
        _mockTemplateRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<ItemTemplate>(), TestWorkspaceId))
            .ReturnsAsync((ItemTemplate?)null);

        // Act
        var result = await _controller.UpdateTemplate(1, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region DeleteTemplate Tests

    [Fact]
    public async Task DeleteTemplate_ReturnsNoContent_WhenTemplateDeleted()
    {
        // Arrange
        _mockTemplateRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteTemplate(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task DeleteTemplate_ReturnsNotFound_WhenTemplateDoesNotExist()
    {
        // Arrange
        _mockTemplateRepository.Setup(repo => repo.DeleteAsync(999, TestWorkspaceId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteTemplate(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteTemplate_ReturnsNotFound_WhenDeletingSystemTemplate()
    {
        // Arrange - Repository returns false for system templates (they can't be deleted)
        _mockTemplateRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteTemplate(1);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteTemplate_CallsRepositoryWithCorrectWorkspaceId()
    {
        // Arrange
        _mockTemplateRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
            .ReturnsAsync(true);

        // Act
        await _controller.DeleteTemplate(1);

        // Assert
        _mockTemplateRepository.Verify(repo => repo.DeleteAsync(1, TestWorkspaceId), Times.Once);
    }

    #endregion
}
