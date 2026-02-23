using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.BulkUpdate;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Integration tests that verify the full request/response cycle including JSON serialization.
/// </summary>
[Trait("Category", "Integration")]
public class ItemsControllerIntegrationTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ItemsController _controller;
    private readonly JsonSerializerOptions _jsonOptions;
    private const int TestWorkspaceId = 1;
    private const int TestCollectionId = 1;

    public ItemsControllerIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);

        // Set up real repositories
        var mockStatsRepo = new Mock<IWorkspaceStatisticsRepository>().Object;
        var mockCollectionStatsRepo = new Mock<ICollectionStatisticsRepository>().Object;
        var itemRepository = new ItemRepository(_context, mockStatsRepo, mockCollectionStatsRepo, new Mock<ILogger<ItemRepository>>().Object);
        var categoryRepository = new CategoryRepository(_context);
        var collectionRepository = new CollectionRepository(_context, mockStatsRepo, mockCollectionStatsRepo);
        var visibilityService = new VisibilityService();

        _controller = new ItemsController(
            itemRepository,
            categoryRepository,
            collectionRepository,
            visibilityService,
            new BulkUpdateQueue(),
            new Mock<IWorkspaceStatisticsRepository>().Object,
            new Mock<ICollectionStatisticsRepository>().Object);

        // Configure claims
        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };

        // Match the JSON options used in Program.cs
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        // Seed test data
        SeedTestData();
    }

    private void SeedTestData()
    {
        var workspace = new Workspace { Id = TestWorkspaceId, Name = "Test Workspace" };
        _context.Workspaces.Add(workspace);

        var collection = new Collection
        {
            Id = TestCollectionId,
            WorkspaceId = TestWorkspaceId,
            Name = "Test Collection",
            Slug = "test"
        };
        _context.Collections.Add(collection);

        _context.SaveChanges();
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    [Fact]
    public async Task CreateItem_WithUserFlag_PersistsAndReturnsFlag()
    {
        // Arrange - Simulate the JSON that the frontend would send
        var requestJson = """
        {
            "name": "Test Item",
            "summary": "Test summary",
            "description": "Test description",
            "collectionId": 1,
            "categoryId": null,
            "properties": [],
            "images": [],
            "isPublicOverride": null,
            "userFlag": 2
        }
        """;

        var request = JsonSerializer.Deserialize<CreateItemRequest>(requestJson, _jsonOptions);

        // Act
        var result = await _controller.CreateItem(request!);

        // Assert - Verify the controller returns the item with the flag
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(createdResult.Value);
        Assert.Equal(UserFlag.Want, returnedItem.UserFlag);

        // Verify the response JSON would include userFlag
        var responseJson = JsonSerializer.Serialize(returnedItem, _jsonOptions);
        Assert.Contains("\"userFlag\"", responseJson);

        // Verify it's persisted in the database
        var savedItem = await _context.Items.FindAsync(returnedItem.Id);
        Assert.Equal(UserFlag.Want, savedItem!.UserFlag);
    }

    [Fact]
    public async Task UpdateItem_WithUserFlag_PersistsAndReturnsFlag()
    {
        // Arrange - Create an item with Have flag first
        var existingItem = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Existing Item",
            UserFlag = UserFlag.Have
        };
        _context.Items.Add(existingItem);
        await _context.SaveChangesAsync();
        var itemId = existingItem.Id!.Value;
        _context.Entry(existingItem).State = EntityState.Detached;

        // Simulate the JSON that the frontend would send for update
        var requestJson = $$$"""
        {
            "name": "Updated Item",
            "summary": "Updated summary",
            "description": "Updated description",
            "collectionId": 1,
            "categoryId": null,
            "properties": [],
            "images": [],
            "isPublicOverride": null,
            "userFlag": 3
        }
        """;

        var request = JsonSerializer.Deserialize<UpdateItemRequest>(requestJson, _jsonOptions);

        // Act
        var result = await _controller.UpdateItem(itemId, request!);

        // Assert - Verify the controller returns the item with the updated flag
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(okResult.Value);
        Assert.Equal(UserFlag.TradeOrSell, returnedItem.UserFlag);

        // Verify the response JSON would include userFlag
        var responseJson = JsonSerializer.Serialize(returnedItem, _jsonOptions);
        Assert.Contains("\"userFlag\"", responseJson);

        // Verify it's persisted in the database
        var savedItem = await _context.Items.FindAsync(itemId);
        Assert.Equal(UserFlag.TradeOrSell, savedItem!.UserFlag);
    }

    [Fact]
    public async Task GetItem_ReturnsUserFlag()
    {
        // Arrange - Create an item with a specific flag
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item with Flag",
            UserFlag = UserFlag.Have
        };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();
        var itemId = item.Id!.Value;

        // Act
        var result = await _controller.GetItem(itemId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(okResult.Value);
        Assert.Equal(UserFlag.Have, returnedItem.UserFlag);

        // Verify the response JSON includes userFlag
        var responseJson = JsonSerializer.Serialize(returnedItem, _jsonOptions);
        Assert.Contains("\"userFlag\"", responseJson);
        Assert.Contains("\"Have\"", responseJson); // JsonStringEnumConverter should output string
    }

    [Fact]
    public async Task FullRoundTrip_CreateReadUpdateRead_PreservesUserFlag()
    {
        // Step 1: Create item with Want flag
        var createJson = """
        {
            "name": "Round Trip Item",
            "collectionId": 1,
            "userFlag": 2
        }
        """;
        var createRequest = JsonSerializer.Deserialize<CreateItemRequest>(createJson, _jsonOptions);
        var createResult = await _controller.CreateItem(createRequest!);
        var createdItem = ((CreatedAtActionResult)createResult.Result!).Value as Item;
        var itemId = createdItem!.Id!.Value;

        Assert.Equal(UserFlag.Want, createdItem.UserFlag);

        // Step 2: Read the item
        var getResult1 = await _controller.GetItem(itemId);
        var readItem1 = ((OkObjectResult)getResult1.Result!).Value as Item;
        Assert.Equal(UserFlag.Want, readItem1!.UserFlag);

        // Step 3: Update to TradeOrSell
        var updateJson = """
        {
            "name": "Round Trip Item Updated",
            "collectionId": 1,
            "userFlag": 3
        }
        """;
        var updateRequest = JsonSerializer.Deserialize<UpdateItemRequest>(updateJson, _jsonOptions);
        var updateResult = await _controller.UpdateItem(itemId, updateRequest!);
        var updatedItem = ((OkObjectResult)updateResult.Result!).Value as Item;
        Assert.Equal(UserFlag.TradeOrSell, updatedItem!.UserFlag);

        // Step 4: Read again to verify persistence
        var getResult2 = await _controller.GetItem(itemId);
        var readItem2 = ((OkObjectResult)getResult2.Result!).Value as Item;
        Assert.Equal(UserFlag.TradeOrSell, readItem2!.UserFlag);
    }

    [Fact]
    public async Task CreateItem_WithTemplateKey_RecordsTemplateKey()
    {
        // Arrange - Create an item template first
        var templateKey = Guid.NewGuid();
        var template = new ItemTemplate
        {
            WorkspaceId = TestWorkspaceId,
            TemplateKey = templateKey,
            Name = "Test Template",
            Description = "A test template"
        };
        _context.ItemTemplates.Add(template);
        await _context.SaveChangesAsync();

        // Create item request with the template key
        var request = new CreateItemRequest
        {
            Name = "Item From Template",
            Summary = "Created from a template",
            CollectionId = TestCollectionId,
            TemplateKey = templateKey,
            Properties = new List<ItemProperty>
            {
                new("Details", "Author", "Test Author")
            }
        };

        // Act
        var result = await _controller.CreateItem(request);

        // Assert - Verify the controller returns the item with the template key
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(createdResult.Value);
        Assert.Equal(templateKey, returnedItem.TemplateKey);

        // Verify the response JSON includes templateKey
        var responseJson = JsonSerializer.Serialize(returnedItem, _jsonOptions);
        Assert.Contains("\"templateKey\"", responseJson);
        Assert.Contains(templateKey.ToString(), responseJson);

        // Verify it's persisted in the database
        var savedItem = await _context.Items.FindAsync(returnedItem.Id);
        Assert.Equal(templateKey, savedItem!.TemplateKey);
    }

    [Fact]
    public async Task CreateItem_WithoutTemplateKey_HasNullTemplateKey()
    {
        // Arrange - Create item without template key (from scratch)
        var request = new CreateItemRequest
        {
            Name = "Item From Scratch",
            Summary = "Created without a template",
            CollectionId = TestCollectionId,
            TemplateKey = null
        };

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(createdResult.Value);
        Assert.Null(returnedItem.TemplateKey);

        // Verify it's persisted as null in the database
        var savedItem = await _context.Items.FindAsync(returnedItem.Id);
        Assert.Null(savedItem!.TemplateKey);
    }

    [Fact]
    public async Task CreateItem_TemplateKeyPersistsAfterTemplateDeleted()
    {
        // Arrange - Create a template
        var templateKey = Guid.NewGuid();
        var template = new ItemTemplate
        {
            WorkspaceId = TestWorkspaceId,
            TemplateKey = templateKey,
            Name = "Deletable Template"
        };
        _context.ItemTemplates.Add(template);
        await _context.SaveChangesAsync();
        var templateId = template.Id;

        // Create an item from the template
        var request = new CreateItemRequest
        {
            Name = "Item With Template Reference",
            CollectionId = TestCollectionId,
            TemplateKey = templateKey
        };
        var createResult = await _controller.CreateItem(request);
        var createdItem = ((CreatedAtActionResult)createResult.Result!).Value as Item;
        var itemId = createdItem!.Id!.Value;

        // Act - Delete the template
        var templateToDelete = await _context.ItemTemplates.FindAsync(templateId);
        _context.ItemTemplates.Remove(templateToDelete!);
        await _context.SaveChangesAsync();

        // Assert - Item still has the template key (soft reference survives deletion)
        var savedItem = await _context.Items.FindAsync(itemId);
        Assert.Equal(templateKey, savedItem!.TemplateKey);

        // Read via controller
        var getResult = await _controller.GetItem(itemId);
        var returnedItem = ((OkObjectResult)getResult.Result!).Value as Item;
        Assert.Equal(templateKey, returnedItem!.TemplateKey);
    }
}
