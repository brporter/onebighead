namespace OneBigHead.Server.Services.Matching;

public class LlmMatchResult
{
    public int ItemId { get; set; }
    public double ConfidenceScore { get; set; }
    public string Reason { get; set; } = string.Empty;
}
