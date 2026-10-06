namespace OneBigHead.Server.Middleware;

/// <summary>Allows account recovery and workspace setup without an active workspace.</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class AllowInactiveWorkspaceAttribute : Attribute;
