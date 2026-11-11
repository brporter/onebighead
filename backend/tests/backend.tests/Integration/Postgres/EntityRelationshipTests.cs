using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
public class EntityRelationshipTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CollectionTemplateAndThemeNavigations_RoundTripThroughTheirForeignKeys()
    {
        await using (var context = fixture.CreateContext())
        {
            var workspace = new Workspace { Name = "Workspace" };
            var collection = new Collection { Name = "Books", Slug = "books", Workspace = workspace };
            var category = new Category { Name = "Fiction", Collection = collection, Workspace = workspace };
            var template = new ItemTemplate { Name = "Book", TemplateKey = Guid.NewGuid(), Workspace = workspace };
            var theme = new CollectionTheme { Name = "Library" };
            context.CollectionItemTemplates.Add(new CollectionItemTemplate { Collection = collection, ItemTemplate = template });
            context.CategoryItemTemplates.Add(new CategoryItemTemplate { Category = category, ItemTemplate = template });
            context.ItemTemplateProperties.Add(new ItemTemplateProperty { ItemTemplate = template, Category = "Details", Name = "Author" });
            context.CollectionThemeCategories.Add(new CollectionThemeCategory { Theme = theme, Name = "Fiction" });
            context.CollectionThemeTemplates.Add(new CollectionThemeTemplate { Theme = theme, ItemTemplate = template });
            context.PropertySuggestions.Add(new PropertySuggestion { Workspace = workspace, Collection = collection,
                Type = PropertySuggestionType.Name, Value = "Author" });
            context.StoredImages.Add(new StoredImage { Id = Guid.NewGuid(), Workspace = workspace, FileName = "book.png", ContentType = "image/png", Data = [1, 2] });
            await context.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var collectionLink = await read.CollectionItemTemplates.Include(link => link.Collection).Include(link => link.ItemTemplate).SingleAsync();
        Assert.Equal("Books", collectionLink.Collection!.Name);
        Assert.Equal(collectionLink.CollectionId, collectionLink.Collection.Id);
        Assert.Equal("Book", collectionLink.ItemTemplate!.Name);
        Assert.Equal(collectionLink.ItemTemplateId, collectionLink.ItemTemplate.Id);

        var categoryLink = await read.CategoryItemTemplates.Include(link => link.Category).Include(link => link.ItemTemplate).SingleAsync();
        Assert.Equal("Fiction", categoryLink.Category!.Name);
        Assert.Equal(categoryLink.CategoryId, categoryLink.Category.Id);
        Assert.Same(collectionLink.ItemTemplate, categoryLink.ItemTemplate);
        Assert.Equal(categoryLink.ItemTemplateId, categoryLink.ItemTemplate!.Id);
        var templateProperty = await read.ItemTemplateProperties.Include(property => property.ItemTemplate).SingleAsync();
        Assert.Same(collectionLink.ItemTemplate, templateProperty.ItemTemplate);
        var persistedTemplate = await read.ItemTemplates.Include(entity => entity.Workspace).SingleAsync();
        Assert.Equal("Workspace", persistedTemplate.Workspace!.Name);
        Assert.Equal(persistedTemplate.WorkspaceId, persistedTemplate.Workspace.Id);

        var themeCategory = await read.CollectionThemeCategories.Include(category => category.Theme).SingleAsync();
        var themeTemplate = await read.CollectionThemeTemplates.Include(link => link.Theme).SingleAsync();
        Assert.Equal("Library", themeCategory.Theme!.Name);
        Assert.Equal(themeCategory.ThemeId, themeCategory.Theme.Id);
        Assert.Same(themeCategory.Theme, themeTemplate.Theme);
        Assert.Equal(themeTemplate.ThemeId, themeTemplate.Theme!.Id);
        var suggestion = await read.PropertySuggestions.Include(entity => entity.Workspace).Include(entity => entity.Collection).SingleAsync();
        Assert.Same(persistedTemplate.Workspace, suggestion.Workspace);
        Assert.Same(collectionLink.Collection, suggestion.Collection);
        Assert.Equal(suggestion.WorkspaceId, suggestion.Workspace!.Id);
        Assert.Equal(suggestion.CollectionId, suggestion.Collection!.Id);
        var image = await read.StoredImages.Include(entity => entity.Workspace).SingleAsync();
        Assert.Same(persistedTemplate.Workspace, image.Workspace);
        Assert.Equal(image.WorkspaceId, image.Workspace!.Id);
        Assert.Equal(new byte[] { 1, 2 }, image.Data);
    }

    [Fact]
    public async Task SupportAndRevocationRecords_RoundTripTheirUserAndRequestRelationships()
    {
        await using (var context = fixture.CreateContext())
        {
            var user = new User { Id = 1, Email = "reader@example.com" };
            var request = new SupportRequest { User = user, Email = user.Email, Subject = "Help", Description = "Question" };
            context.SupportReplies.Add(new SupportReply { User = user, SupportRequest = request, Message = "More details" });
            context.TokenRevocations.Add(new TokenRevocation { UserId = 1, RevokedAtUtc = DateTime.UtcNow });
            await context.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var reply = await read.SupportReplies.Include(entity => entity.User).Include(entity => entity.SupportRequest)!
            .ThenInclude(request => request!.User).SingleAsync();
        Assert.Equal("reader@example.com", reply.User!.Email);
        Assert.Equal(reply.UserId, reply.User.Id);
        Assert.Equal("Help", reply.SupportRequest!.Subject);
        Assert.Equal(reply.SupportRequestId, reply.SupportRequest.Id);
        Assert.Same(reply.User, reply.SupportRequest.User);
        var revocation = await read.TokenRevocations.SingleAsync();
        Assert.True(revocation.Id > 0);
        Assert.Equal(reply.User.Id, revocation.UserId);
    }
}
