namespace OneBigHead.Server.Services.Memberships;

public enum TeamMembershipStatus { Changed, NotFound, Forbidden, Invalid, Conflict }

public sealed record TeamMembershipResult(TeamMembershipStatus Status, string? Error = null);
