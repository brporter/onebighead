using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Support;

public sealed class SupportRequestCreator(ISupportRepository requests, IUserRepository users, IEmailService email) : ISupportRequestCreator
{
    public async Task<SupportCreationResult> CreateAsync(int? userId, CreateSupportRequestDto draft)
    {
        string address;
        if (userId.HasValue)
        {
            var user = await users.GetByIdAsync(userId.Value);
            if (user is null) return new(SupportCreationStatus.UnknownUser);
            address = user.Email;
        }
        else
        {
            if (string.IsNullOrWhiteSpace(draft.Email)) return new(SupportCreationStatus.MissingEmail);
            address = draft.Email;
        }

        var created = await requests.CreateRequestAsync(new SupportRequest
        {
            UserId = userId, Email = address, Subject = draft.Subject, Description = draft.Description, Status = SupportRequestStatus.Open,
        });
        await email.SendSupportRequestConfirmationAsync(address, draft.Subject, created.Id, userId.HasValue);
        return new(SupportCreationStatus.Created, created);
    }
}
