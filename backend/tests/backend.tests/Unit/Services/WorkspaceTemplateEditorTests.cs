using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Templates;

namespace OneBigHead.Server.Tests.Unit.Services;

public class WorkspaceTemplateEditorTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Update_SelectsCopyOnEditOnlyForSharedTemplatesAndReturnsThePersistedIdentity(bool shared)
    {
        var templates = new Mock<IItemTemplateRepository>();
        var source = new ItemTemplate { Id = 4, WorkspaceId = shared ? null : 7, Name = "Original" };
        var stored = new ItemTemplate { Id = shared ? 20 : 4, WorkspaceId = 7, Name = "Saved" };
        templates.Setup(repository => repository.GetByIdAsync(4, 7)).ReturnsAsync(source);
        templates.Setup(repository => repository.CopySystemTemplateAsync(4, 7, It.IsAny<ItemTemplate>())).ReturnsAsync(stored);
        templates.Setup(repository => repository.UpdateAsync(4, It.IsAny<ItemTemplate>(), 7)).ReturnsAsync(stored);

        var result = await new WorkspaceTemplateEditor(templates.Object).UpdateAsync(7, 4, new UpdateItemTemplateRequest { Name = "Saved" });

        Assert.Same(stored, result);
        Assert.Equal("Original", source.Name);
        templates.Verify(repository => repository.CopySystemTemplateAsync(4, 7, It.Is<ItemTemplate>(template => template.Name == "Saved")), shared ? Times.Once() : Times.Never());
        templates.Verify(repository => repository.UpdateAsync(4, It.Is<ItemTemplate>(template => template.Name == "Saved"), 7), shared ? Times.Never() : Times.Once());
    }

    [Fact]
    public async Task Create_AssignsWorkspaceOwnershipAndAnIndependentTemplateKey()
    {
        var templates = new Mock<IItemTemplateRepository>();
        templates.Setup(repository => repository.CreateAsync(It.IsAny<ItemTemplate>())).ReturnsAsync((ItemTemplate template) => template);
        var editor = new WorkspaceTemplateEditor(templates.Object);
        var draft = new CreateItemTemplateRequest { Name = "Books" };
        var first = await editor.CreateAsync(7, draft);
        var second = await editor.CreateAsync(9, draft);
        Assert.Equal(7, first.WorkspaceId);
        Assert.Equal(9, second.WorkspaceId);
        Assert.NotEqual(first.TemplateKey, second.TemplateKey);
        Assert.Equal("Books", first.Name);
    }

    [Fact]
    public async Task MissingTemplate_CannotBeCreatedByAnUpdate()
    {
        var templates = new Mock<IItemTemplateRepository>(MockBehavior.Strict);
        templates.Setup(repository => repository.GetByIdAsync(4, 7)).ReturnsAsync((ItemTemplate?)null);
        Assert.Null(await new WorkspaceTemplateEditor(templates.Object).UpdateAsync(7, 4, new UpdateItemTemplateRequest { Name = "Saved" }));
        templates.Verify(repository => repository.GetByIdAsync(4, 7), Times.Once);
        templates.VerifyNoOtherCalls();
    }
}
