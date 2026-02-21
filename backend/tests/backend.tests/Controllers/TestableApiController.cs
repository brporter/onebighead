using OneBigHead.Server.Controllers;

namespace OneBigHead.Server.Tests.Controllers;

public class TestableApiController : ApiControllerBase
{
    public int TestGetWorkspaceId() => GetWorkspaceId();
    public int? TestTryGetWorkspaceId() => TryGetWorkspaceId();
    public int TestGetUserId() => GetUserId();
}