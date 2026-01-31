using backend.Controllers;
using backend.Data;
using backend.DTOs;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace backend.Tests.Integration;

/// <summary>
/// Integration tests that verify the full request/response cycle including JSON serialization.
/// </summary>
[Trait("Category", "Integration")]
public class ItemsControllerIntegrationTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ItemsController _controller;
    private readonly JsonSerializerOptions _jsonOptions;
    private const int TestTenantId = 1;
    private const int TestCollectionId = 1;

    public ItemsControllerIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);

        // Set up real repositories
        var itemRepository = new ItemRepository(_context);
        var categoryRepository = new CategoryRepository(_context);
        var collectionRepository = new CollectionRepository(_context);
        var visibilityService = new VisibilityService();

        _controller = new ItemsController(
            itemRepository,
            categoryRepository,
            collectionRepository,
            visibilityService);

        // Configure claims
        var claims = new List<Claim>
        {
            new("tenant_id", TestTenantId.ToString()),
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
        var tenant = new Tenant { Id = TestTenantId, Name = "Test Tenant" };
        _context.Tenants.Add(tenant);

        var collection = new Collection
        {
            Id = TestCollectionId,
            TenantId = TestTenantId,
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
        // Arrange - Create an item with None flag first
        var existingItem = new Item
        {
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Existing Item",
            UserFlag = UserFlag.None
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
            TenantId = TestTenantId,
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
}
