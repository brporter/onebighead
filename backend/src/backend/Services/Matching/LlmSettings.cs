namespace OneBigHead.Server.Services.Matching;

public class LlmSettings
{
    public string Endpoint { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public string DeploymentName { get; set; } = "gpt-4o-mini";
    /// <summary>
    /// Optional separate endpoint for the embedding model.
    /// Falls back to <see cref="Endpoint"/> if not set.
    /// </summary>
    public string EmbeddingEndpoint { get; set; } = string.Empty;
    /// <summary>
    /// Optional separate API key for the embedding endpoint.
    /// Falls back to <see cref="ApiKey"/> if not set.
    /// </summary>
    public string EmbeddingApiKey { get; set; } = string.Empty;
    public string EmbeddingDeploymentName { get; set; } = "text-embedding-3-small";
    public double ConfidenceThreshold { get; set; } = 0.6;
    public int MaxCandidatesPerBatch { get; set; } = 10;
    public double SimilarityThreshold { get; set; } = 0.5;
    public bool Enabled { get; set; } = false;

    /// <summary>Resolved embedding endpoint (own value or fallback to shared).</summary>
    public string ResolvedEmbeddingEndpoint =>
        string.IsNullOrEmpty(EmbeddingEndpoint) ? Endpoint : EmbeddingEndpoint;

    /// <summary>Resolved embedding API key (own value or fallback to shared).</summary>
    public string ResolvedEmbeddingApiKey =>
        string.IsNullOrEmpty(EmbeddingApiKey) ? ApiKey : EmbeddingApiKey;
}
