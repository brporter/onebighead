using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.HttpResults;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapGet("/", Results<RedirectHttpResult, IResult> () 
        => TypedResults.Redirect("https://localhost:5173/", permanent:false));
}

Todo[] sampleTodos =
[
    new(1, "Walk the dog"),
    new(2, "Do the dishes", DateOnly.FromDateTime(DateTime.Now)),
    new(3, "Do the laundry", DateOnly.FromDateTime(DateTime.Now.AddDays(1))),
    new(4, "Clean the bathroom"),
    new(5, "Clean the car", DateOnly.FromDateTime(DateTime.Now.AddDays(2)))
];

Category[] sampleCategories = [
        new(1, 1, "Motorola 68000 Computers", "Some Description", null),
        new(2, 1, "Compact Macintosh", "Some description", 1),
        new(3, 1, "Apple II", "Some description", 1),
        new(4, 1, "Peripherals", "Some description", null),
        new(5, 1, "Monitors", "Some description", 4),
        new(6, 1, "Printers", "Some description", 4),
        new(7, 1, "Intel Computers", "Some description", null)
];

var categoriesApi = app.MapGroup("/categories");
categoriesApi.MapGet("/", () => sampleCategories)
        .WithName("GetCategories");


var todosApi = app.MapGroup("/todos");
todosApi.MapGet("/", () => sampleTodos)
        .WithName("GetTodos");

todosApi.MapGet("/{id}", Results<Ok<Todo>, NotFound> (int id) =>
    sampleTodos.FirstOrDefault(a => a.Id == id) is { } todo
        ? TypedResults.Ok(todo)
        : TypedResults.NotFound())
    .WithName("GetTodoById");

app.Run();

public record Category(
    [property: JsonPropertyName("categoryId")]int Id, 
    int TenantId, 
    string Name, 
    string Description, 
    int? ParentCategoryId = null);

public record Todo(int Id, string? Title, DateOnly? DueBy = null, bool IsComplete = false);

[JsonSerializable(typeof(Todo[])), JsonSerializable(typeof(Category[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{

}
