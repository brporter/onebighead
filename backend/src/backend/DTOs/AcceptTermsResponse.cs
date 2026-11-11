namespace OneBigHead.Server.DTOs;

public sealed record AcceptTermsResponse(bool HasAcceptedTerms, DateTime AcceptedTermsAt);
