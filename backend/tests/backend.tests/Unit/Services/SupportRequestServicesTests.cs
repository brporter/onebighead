using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Support;

namespace OneBigHead.Server.Tests.Unit.Services;

public class SupportRequestServicesTests
{
    [Theory]
    [InlineData(null, "supplied@example.test")]
    [InlineData(7, "account@example.test")]
    public async Task Create_ResolvesTheContactAddressAndConfirmsOnlyAfterPersistence(int? userId, string address)
    {
        var users = new Mock<IUserRepository>();
        users.Setup(repository => repository.GetByIdAsync(7)).ReturnsAsync(new User { Id = 7, Email = "account@example.test" });
        var requests = new Mock<ISupportRepository>();
        var email = new Mock<IEmailService>();
        var pending = new TaskCompletionSource<SupportRequest>(TaskCreationOptions.RunContinuationsAsynchronously);
        requests.Setup(repository => repository.CreateRequestAsync(It.Is<SupportRequest>(request => request.UserId == userId && request.Email == address && request.Status == SupportRequestStatus.Open)))
            .Returns(pending.Task);
        var draft = new CreateSupportRequestDto { Email = "supplied@example.test", Subject = "Question", Description = "Details" };
        var creating = new SupportRequestCreator(requests.Object, users.Object, email.Object).CreateAsync(userId, draft);
        email.VerifyNoOtherCalls();
        Assert.False(creating.IsCompleted);
        var stored = new SupportRequest { Id = 12, UserId = userId, Email = address, Subject = draft.Subject, Description = draft.Description };
        pending.SetResult(stored);
        var result = await creating;
        Assert.Equal(SupportCreationStatus.Created, result.Status);
        Assert.Same(stored, result.Request);
        email.Verify(service => service.SendSupportRequestConfirmationAsync(address, "Question", 12, userId.HasValue), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_DoesNotReplayPersistenceWhenSavingOrConfirmationFails(bool confirmationFailure)
    {
        var users = new Mock<IUserRepository>();
        var requests = new Mock<ISupportRepository>();
        var email = new Mock<IEmailService>();
        var failure = new InvalidOperationException("Unavailable");
        if (confirmationFailure)
        {
            requests.Setup(repository => repository.CreateRequestAsync(It.IsAny<SupportRequest>())).ReturnsAsync(new SupportRequest { Id = 12 });
            email.Setup(service => service.SendSupportRequestConfirmationAsync("email@example.test", "Question", 12, false)).ThrowsAsync(failure);
        }
        else requests.Setup(repository => repository.CreateRequestAsync(It.IsAny<SupportRequest>())).ThrowsAsync(failure);

        var creator = new SupportRequestCreator(requests.Object, users.Object, email.Object);
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => creator.CreateAsync(null,
            new CreateSupportRequestDto { Email = "email@example.test", Subject = "Question" })));
        requests.Verify(repository => repository.CreateRequestAsync(It.IsAny<SupportRequest>()), Times.Once);
        email.Verify(service => service.SendSupportRequestConfirmationAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), false), confirmationFailure ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(false, null, false)]
    [InlineData(true, null, false)]
    [InlineData(true, 8, false)]
    [InlineData(true, 7, true)]
    public async Task OwnershipPolicy_IsSharedByReadsDeletionAndReadReceipts(bool exists, int? owner, bool allowed)
    {
        var repository = new Mock<ISupportRepository>();
        var request = exists ? new SupportRequest { Id = 12, UserId = owner } : null;
        repository.Setup(source => source.GetRequestByIdAsync(12, It.IsAny<bool>())).ReturnsAsync(request);
        var service = new SupportRequests(repository.Object);
        Assert.Same(allowed ? request : null, await service.GetAsync(12, 7));
        Assert.Equal(allowed, await service.DeleteAsync(12, 7));
        Assert.Equal(allowed, await service.MarkReadAsync(12, 7));
        repository.Verify(source => source.GetRequestByIdAsync(12, true), Times.Once);
        repository.Verify(source => source.GetRequestByIdAsync(12, false), Times.Exactly(2));
        repository.Verify(source => source.SoftDeleteAsync(12), allowed ? Times.Once() : Times.Never());
        repository.Verify(source => source.MarkRepliesAsReadAsync(12, 7), allowed ? Times.Once() : Times.Never());
    }
}
