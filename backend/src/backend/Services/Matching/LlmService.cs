using System.Text;
using System.Text.Json;
using OneBigHead.Server.Models;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Services.Matching;

public class LlmService : ILlmService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LlmSettings _settings;
    private readonly ILogger<LlmService> _logger;

    public LlmService(
        IHttpClientFactory httpClientFactory,
        IOptions<LlmSettings> settings,
        ILogger<LlmService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task<List<LlmMatchResult>> EvaluateMatchesAsync(
        Item wantItem, List<Item> candidates, CancellationToken ct = default)
    {
        if (candidates.Count == 0)
            return [];

        var client = _httpClientFactory.CreateClient("AzureOpenAI");

        var systemPrompt = BuildSystemPrompt();
        var userPrompt = BuildUserPrompt(wantItem, candidates);

        var requestBody = new
        {
            messages = new object[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = userPrompt }
            },
            temperature = 0.1,
            response_format = new { type = "json_object" }
        };

        var requestUrl = $"{_settings.Endpoint.TrimEnd('/')}/openai/deployments/{_settings.DeploymentName}/chat/completions?api-version=2024-02-01";

        var content = new StringContent(
            JsonSerializer.Serialize(requestBody),
            Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync(requestUrl, content, ct);
        response.EnsureSuccessStatusCode();

        var responseBody = await response.Content.ReadAsStringAsync(ct);
        return ParseLlmResponse(responseBody);
    }

    private static string BuildSystemPrompt()
    {
        return """
            You are an item matching assistant. You evaluate whether trade/sell items match what a user is looking for.
            For each candidate, provide a confidence score (0.0 to 1.0) and a brief reason.
            A score of 0.8+ means strong match, 0.5-0.8 means possible match, below 0.5 means unlikely match.
            Consider item names, descriptions, properties, and semantic similarity.
            Respond with JSON in this format:
            { "matches": [ { "itemId": 123, "confidence": 0.85, "reason": "Brief explanation" } ] }
            """;
    }

    private static string BuildUserPrompt(Item wantItem, List<Item> candidates)
    {
        var sb = new StringBuilder();
        sb.AppendLine("WANTED ITEM:");
        sb.AppendLine($"  Name: {wantItem.Name}");
        if (!string.IsNullOrWhiteSpace(wantItem.Summary))
            sb.AppendLine($"  Summary: {wantItem.Summary}");
        if (!string.IsNullOrWhiteSpace(wantItem.Description))
            sb.AppendLine($"  Description: {wantItem.Description}");
        foreach (var prop in wantItem.Properties)
            sb.AppendLine($"  {prop.Name}: {prop.Value}");

        sb.AppendLine();
        sb.AppendLine("CANDIDATE ITEMS FOR TRADE/SELL:");

        foreach (var candidate in candidates)
        {
            sb.AppendLine($"  Item ID: {candidate.Id}");
            sb.AppendLine($"    Name: {candidate.Name}");
            if (!string.IsNullOrWhiteSpace(candidate.Summary))
                sb.AppendLine($"    Summary: {candidate.Summary}");
            if (!string.IsNullOrWhiteSpace(candidate.Description))
                sb.AppendLine($"    Description: {candidate.Description}");
            foreach (var prop in candidate.Properties)
                sb.AppendLine($"    {prop.Name}: {prop.Value}");
            sb.AppendLine();
        }

        sb.AppendLine("Evaluate each candidate against the wanted item. Return confidence scores and reasons.");
        return sb.ToString();
    }

    private List<LlmMatchResult> ParseLlmResponse(string responseBody)
    {
        var results = new List<LlmMatchResult>();

        try
        {
            using var doc = JsonDocument.Parse(responseBody);
            var messageContent = doc.RootElement
                .GetProperty("choices")[0]
                .GetProperty("message")
                .GetProperty("content")
                .GetString();

            if (string.IsNullOrEmpty(messageContent))
                return results;

            using var matchDoc = JsonDocument.Parse(messageContent);
            var matches = matchDoc.RootElement.GetProperty("matches");

            foreach (var match in matches.EnumerateArray())
            {
                results.Add(new LlmMatchResult
                {
                    ItemId = match.GetProperty("itemId").GetInt32(),
                    ConfidenceScore = match.GetProperty("confidence").GetDouble(),
                    Reason = match.GetProperty("reason").GetString() ?? string.Empty
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse LLM response");
        }

        return results;
    }
}
