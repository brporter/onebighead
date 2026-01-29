namespace backend.Services;

public class EmailSettings
{
    /// <summary>
    /// Azure Communication Services connection string.
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// The sender email address (must be verified in Azure Communication Services).
    /// </summary>
    public string SenderAddress { get; set; } = "noreply@onebighead.com";

    /// <summary>
    /// Base URL of the application (for links in emails).
    /// </summary>
    public string AppBaseUrl { get; set; } = "https://onebighead.com";
}
