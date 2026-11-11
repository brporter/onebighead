using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Templates;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class SystemTemplateServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly Guid Origin = Guid.Parse("46feeb0b-f48b-4620-8ac6-058b9c146ae0");
    private static readonly DateTime Created = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private SystemTemplateService Service() => new(fixture.CreateContextFactory(), new FixedTime());

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Library" });
        context.Collections.Add(new Collection { Id = 1, WorkspaceId = 1, Name = "Books", Slug = "books" });
        context.Categories.Add(new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Fiction" });
        context.ItemTemplates.AddRange(
            new ItemTemplate { Id = 1, Name = "Books", Description = "Old definition", TemplateKey = Origin, CreatedAt = Created, UpdatedAt = Created,
                Properties = [new() { Category = "Details", Name = "Publisher", SortOrder = 10 }, new() { Category = "Details", Name = "Author", SortOrder = 2 }] },
            new ItemTemplate { Id = 2, Name = "Archive", TemplateKey = Guid.NewGuid() },
            new ItemTemplate { Id = 3, WorkspaceId = 1, Name = "Private template", TemplateKey = Guid.NewGuid(),
                Properties = [new() { Category = "Private", Name = "Note" }] });
        context.CollectionItemTemplates.AddRange(new CollectionItemTemplate { CollectionId = 1, ItemTemplateId = 1 },
            new CollectionItemTemplate { CollectionId = 1, ItemTemplateId = 3 });
        context.CategoryItemTemplates.AddRange(new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1 },
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 3 });
        context.CollectionThemes.Add(new CollectionTheme { Id = 1, Name = "Reading", ThemeTemplates = [new() { ItemTemplateId = 1 }, new() { ItemTemplateId = 2 }] });
        context.Items.Add(new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Name = "Existing book", TemplateKey = Origin,
            Properties = [new("Details", "Author", "Reader")] });
        await context.SaveChangesAsync();
        await context.Database.ExecuteSqlRawAsync("ALTER SEQUENCE \"ItemTemplates_Id_seq\" RESTART WITH 10");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Reads_OnlySharedTemplates_WithDeterministicPropertyOrder()
    {
        var list = await Service().GetAllAsync();
        Assert.Equal(new[] { "Archive", "Books" }, list.Select(t => t.Name));
        Assert.All(list, t => Assert.True(t.IsSystem));
        var template = await Service().GetAsync(1);
        Assert.NotNull(template);
        Assert.Equal(Origin, template.TemplateKey);
        Assert.Equal(Created, template.CreatedAt);
        Assert.Equal(new[] { "Author", "Publisher" }, template.Properties.Select(p => p.Name));
    }

    [Fact]
    public async Task EmptyCatalog_ReturnsAnEmptyList()
    {
        await fixture.ResetAsync();
        Assert.Empty(await Service().GetAllAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_PersistsSystemIdentityAndOrderedDefinition(bool withProperties)
    {
        var response = await Service().CreateAsync(Definition(withProperties));
        Assert.True(response.IsSystem);
        Assert.NotEqual(Guid.Empty, response.TemplateKey);
        Assert.Equal(Now.UtcDateTime, response.CreatedAt);
        Assert.Equal(Now.UtcDateTime, response.UpdatedAt);
        await using var context = fixture.CreateContext();
        var saved = await context.ItemTemplates.Include(t => t.Properties).SingleAsync(t => t.Id == response.ItemTemplateId);
        Assert.Null(saved.WorkspaceId);
        Assert.Equal(response.TemplateKey, saved.TemplateKey);
        Assert.Equal("Updated definition", saved.Name);
        Assert.Equal("A revised description", saved.Description);
        Assert.Equal(withProperties ? new[] { 0, 1 } : [], saved.Properties.OrderBy(p => p.SortOrder).Select(p => p.SortOrder));
        Assert.Equal(withProperties ? new[] { "Edition", "Publisher" } : [], response.Properties.Select(p => p.Name));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Update_ReplacesPropertiesAndPreservesIdentityAndExistingItems(bool withProperties)
    {
        var response = await Service().UpdateAsync(1, Definition(withProperties));
        Assert.NotNull(response);
        Assert.Equal(Origin, response.TemplateKey);
        Assert.Equal(Created, response.CreatedAt);
        Assert.Equal(Now.UtcDateTime, response.UpdatedAt);
        Assert.Equal(withProperties ? new[] { "Edition", "Publisher" } : [], response.Properties.Select(p => p.Name));
        await using var context = fixture.CreateContext();
        var saved = await context.ItemTemplates.Include(t => t.Properties).SingleAsync(t => t.Id == 1);
        Assert.Equal("Updated definition", saved.Name);
        Assert.Equal(response.Properties.Select(p => p.ItemTemplatePropertyId).Order(), saved.Properties.Select(p => p.Id).Order());
        Assert.Equal(withProperties ? new[] { 0, 1 } : [], saved.Properties.OrderBy(p => p.SortOrder).Select(p => p.SortOrder));
        Assert.Equal("Private template", (await context.ItemTemplates.SingleAsync(t => t.Id == 3)).Name);
        Assert.Equal("Reader", Assert.Single((await context.Items.SingleAsync()).Properties).Value);
    }

    [Theory]
    [InlineData(999)]
    [InlineData(3)]
    public async Task MissingAndWorkspaceOwnedTemplates_CannotBeReadChangedOrDeleted(int id)
    {
        var service = Service();
        Assert.Null(await service.GetAsync(id));
        Assert.Null(await service.UpdateAsync(id, Definition(true)));
        Assert.False(await service.DeleteAsync(id));
        await using var context = fixture.CreateContext();
        Assert.Equal(3, await context.ItemTemplates.CountAsync());
        Assert.Equal("Private template", (await context.ItemTemplates.SingleAsync(t => t.Id == 3)).Name);
        Assert.Equal(2, await context.CollectionItemTemplates.CountAsync());
    }

    [Fact]
    public async Task Delete_DetachesOnlyThisDefinition_AndKeepsExistingItems()
    {
        Assert.True(await Service().DeleteAsync(1));
        await using var context = fixture.CreateContext();
        Assert.False(await context.ItemTemplates.AnyAsync(t => t.Id == 1));
        Assert.False(await context.ItemTemplateProperties.AnyAsync(p => p.ItemTemplateId == 1));
        Assert.Equal(3, (await context.CollectionItemTemplates.SingleAsync()).ItemTemplateId);
        Assert.Equal(3, (await context.CategoryItemTemplates.SingleAsync()).ItemTemplateId);
        Assert.Equal(2, (await context.CollectionThemeTemplates.SingleAsync()).ItemTemplateId);
        Assert.Single(await context.Collections.ToListAsync());
        Assert.Single(await context.Categories.ToListAsync());
        var item = await context.Items.SingleAsync();
        Assert.Equal(Origin, item.TemplateKey);
        Assert.Equal("Reader", Assert.Single(item.Properties).Value);
    }

    [Fact]
    public async Task FailedDeletion_RollsBackAssignmentsAlreadyRemovedInsideTheTransaction()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_template_deletion() RETURNS trigger AS $$
            BEGIN
                IF EXISTS (SELECT 1 FROM "CollectionItemTemplates" WHERE "ItemTemplateId" = OLD."Id")
                   OR EXISTS (SELECT 1 FROM "CategoryItemTemplates" WHERE "ItemTemplateId" = OLD."Id") THEN
                    RAISE EXCEPTION 'Assignments have not yet been removed';
                END IF;
                RAISE EXCEPTION 'Failure after assignment deletion' USING ERRCODE = '23514';
            END;
            $$ LANGUAGE plpgsql
            """);
        await context.Database.ExecuteSqlRawAsync("CREATE TRIGGER reject_template_deletion BEFORE DELETE ON \"ItemTemplates\" FOR EACH ROW EXECUTE FUNCTION reject_template_deletion()");
        try
        {
            var error = await Assert.ThrowsAsync<DbUpdateException>(() => Service().DeleteAsync(1));
            var databaseError = Assert.IsType<PostgresException>(error.InnerException);
            Assert.Equal(PostgresErrorCodes.CheckViolation, databaseError.SqlState);
            Assert.Contains("Failure after assignment deletion", databaseError.MessageText);
            Assert.True(await context.ItemTemplates.AnyAsync(t => t.Id == 1));
            Assert.Equal(2, await context.ItemTemplateProperties.CountAsync(p => p.ItemTemplateId == 1));
            Assert.True(await context.CollectionItemTemplates.AnyAsync(t => t.ItemTemplateId == 1));
            Assert.True(await context.CategoryItemTemplates.AnyAsync(t => t.ItemTemplateId == 1));
            Assert.True(await context.CollectionThemeTemplates.AnyAsync(t => t.ItemTemplateId == 1));
            Assert.Equal(Origin, (await context.Items.SingleAsync()).TemplateKey);
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("DROP TRIGGER reject_template_deletion ON \"ItemTemplates\"");
            await context.Database.ExecuteSqlRawAsync("DROP FUNCTION reject_template_deletion()");
        }
    }

    [Fact]
    public async Task FailedReplacement_PreservesThePreviousDefinitionAndProperties()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"ItemTemplateProperties\" ADD CONSTRAINT reject_template_property CHECK (\"Name\" <> 'Edition')");
        try
        {
            await Assert.ThrowsAsync<DbUpdateException>(() => Service().UpdateAsync(1, Definition(true)));
            var saved = await context.ItemTemplates.Include(t => t.Properties).SingleAsync(t => t.Id == 1);
            Assert.Equal("Books", saved.Name);
            Assert.Equal("Old definition", saved.Description);
            Assert.Equal(Created, saved.UpdatedAt);
            Assert.Equal(new[] { "Author", "Publisher" }, saved.Properties.OrderBy(p => p.SortOrder).Select(p => p.Name));
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"ItemTemplateProperties\" DROP CONSTRAINT reject_template_property");
        }
    }

    private static SystemTemplateRequest Definition(bool withProperties) => new()
    {
        Name = "Updated definition", Description = "A revised description",
        Properties = withProperties ? [new() { Category = "Publication", Name = "Edition" }, new() { Category = "Publication", Name = "Publisher" }] : []
    };

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
