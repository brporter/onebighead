namespace OneBigHead.Server.Services.Administration;

public interface IAdministratorAccessService
{
    Task<bool> HasAccessAsync(int userId);
}
