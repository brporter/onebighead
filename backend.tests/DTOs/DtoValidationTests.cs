using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.DTOs;

[Trait("Category", "Unit")]
public class DtoValidationTests
{
    private static IList<ValidationResult> ValidateModel(object model)
    {
        var validationResults = new List<ValidationResult>();
        var validationContext = new ValidationContext(model);
        Validator.TryValidateObject(model, validationContext, validationResults, validateAllProperties: true);
        return validationResults;
    }

    #region TenantRequests Tests

    [Fact]
    public void CreateTenantRequest_RequiresName()
    {
        // Arrange
        var request = new CreateTenantRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateTenantRequest_ValidatesMaxLength()
    {
        // Arrange
        var request = new CreateTenantRequest { Name = new string('A', 201) };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateTenantRequest_ValidWithProperName()
    {
        // Arrange
        var request = new CreateTenantRequest { Name = "My Tenant" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void TenantMembershipResponse_SetsDefaultValues()
    {
        // Arrange & Act
        var response = new TenantMembershipResponse();

        // Assert
        Assert.Equal(0, response.TenantId);
        Assert.Equal(string.Empty, response.TenantName);
        Assert.Equal(default, response.TenantRole);
        Assert.False(response.HasCompletedWelcome);
    }

    [Fact]
    public void CreateTenantResponse_SetsDefaultValues()
    {
        // Arrange & Act
        var response = new CreateTenantResponse();

        // Assert
        Assert.Equal(0, response.TenantId);
        Assert.Equal(string.Empty, response.TenantName);
    }

    [Fact]
    public void SwitchTenantResponse_SetsDefaultValues()
    {
        // Arrange & Act
        var response = new SwitchTenantResponse();

        // Assert
        Assert.False(response.Success);
        Assert.Equal(0, response.TenantId);
        Assert.Equal(string.Empty, response.TenantName);
    }

    [Fact]
    public void LeaveTenantResponse_SetsDefaultValues()
    {
        // Arrange & Act
        var response = new LeaveTenantResponse();

        // Assert
        Assert.False(response.Success);
    }

    #endregion

    #region AdminRequests Tests

    [Fact]
    public void TenantSummaryResponse_SetsDefaultValues()
    {
        // Arrange & Act
        var response = new TenantSummaryResponse();

        // Assert
        Assert.Equal(0, response.TenantId);
        Assert.Equal(string.Empty, response.Name);
        Assert.Equal(0, response.UserCount);
        Assert.Equal(0, response.CollectionCount);
        Assert.Equal(0, response.ItemCount);
        Assert.Equal(0, response.ImageCount);
    }

    [Fact]
    public void UserSummaryResponse_SetsDefaultValues()
    {
        // Arrange & Act
        var response = new UserSummaryResponse();

        // Assert
        Assert.Equal(0, response.UserId);
        Assert.Equal(string.Empty, response.Email);
        Assert.Equal(0, response.TenantId);
        Assert.Equal(string.Empty, response.TenantName);
        Assert.Equal(string.Empty, response.IdentityProvider);
        Assert.False(response.IsSystemAdministrator);
    }

    [Fact]
    public void SetAdminStatusRequest_SetsDefaultValue()
    {
        // Arrange & Act
        var request = new SetAdminStatusRequest();

        // Assert
        Assert.False(request.IsSystemAdministrator);
    }

    [Fact]
    public void SystemTemplateRequest_RequiresName()
    {
        // Arrange
        var request = new SystemTemplateRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void SystemTemplateRequest_ValidatesNameMaxLength()
    {
        // Arrange
        var request = new SystemTemplateRequest { Name = new string('A', 201) };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void SystemTemplateRequest_ValidatesDescriptionMaxLength()
    {
        // Arrange
        var request = new SystemTemplateRequest
        {
            Name = "Valid Name",
            Description = new string('A', 1001)
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Description"));
    }

    [Fact]
    public void SystemTemplateRequest_ValidWithProperValues()
    {
        // Arrange
        var request = new SystemTemplateRequest
        {
            Name = "My Template",
            Description = "Template description",
            Properties = new List<ItemTemplatePropertyDto>()
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    #endregion

    #region SupportRequests Tests

    [Fact]
    public void CreateSupportRequestDto_RequiresSubject()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = "",
            Description = "Description"
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Subject"));
    }

    [Fact]
    public void CreateSupportRequestDto_RequiresDescription()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = "Subject",
            Description = ""
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Description"));
    }

    [Fact]
    public void CreateSupportRequestDto_ValidatesSubjectMaxLength()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = new string('A', 201),
            Description = "Description"
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Subject"));
    }

    [Fact]
    public void CreateSupportRequestDto_ValidatesDescriptionMaxLength()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = "Subject",
            Description = new string('A', 4001)
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Description"));
    }

    [Fact]
    public void CreateSupportRequestDto_ValidatesEmailFormat()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = "Subject",
            Description = "Description",
            Email = "invalid-email"
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Email"));
    }

    [Fact]
    public void CreateSupportRequestDto_AcceptsValidEmail()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = "Subject",
            Description = "Description",
            Email = "user@example.com"
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void CreateSupportReplyDto_RequiresMessage()
    {
        // Arrange
        var request = new CreateSupportReplyDto { Message = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Message"));
    }

    [Fact]
    public void CreateSupportReplyDto_ValidatesMessageMaxLength()
    {
        // Arrange
        var request = new CreateSupportReplyDto { Message = new string('A', 4001) };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Message"));
    }

    #endregion

    #region CollectionRequests Tests

    [Fact]
    public void CreateCollectionRequest_RequiresName()
    {
        // Arrange
        var request = new CreateCollectionRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateCollectionRequest_ValidatesNameMaxLength()
    {
        // Arrange
        var request = new CreateCollectionRequest { Name = new string('A', 201) };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateCollectionRequest_ValidWithProperName()
    {
        // Arrange
        var request = new CreateCollectionRequest { Name = "My Collection" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void UpdateCollectionRequest_RequiresName()
    {
        // Arrange
        var request = new UpdateCollectionRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    #endregion

    #region CategoryRequests Tests

    [Fact]
    public void CreateCategoryRequest_RequiresName()
    {
        // Arrange
        var request = new CreateCategoryRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateCategoryRequest_ValidatesNameMaxLength()
    {
        // Arrange
        var request = new CreateCategoryRequest { Name = new string('A', 201) };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateCategoryRequest_ValidWithProperName()
    {
        // Arrange
        var request = new CreateCategoryRequest { Name = "My Category" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void UpdateCategoryRequest_RequiresName()
    {
        // Arrange
        var request = new UpdateCategoryRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    #endregion

    #region UserRequests Tests

    [Fact]
    public void InviteUserRequest_RequiresEmail()
    {
        // Arrange
        var request = new InviteUserRequest { Email = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Email"));
    }

    [Fact]
    public void InviteUserRequest_ValidatesEmailFormat()
    {
        // Arrange
        var request = new InviteUserRequest { Email = "not-an-email" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Email"));
    }

    [Fact]
    public void InviteUserRequest_AcceptsValidEmail()
    {
        // Arrange
        var request = new InviteUserRequest { Email = "valid@example.com" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    #endregion

    #region ItemRequests Tests

    [Fact]
    public void CreateItemRequest_RequiresName()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "",
            CollectionId = 1
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateItemRequest_ValidatesNameMaxLength()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = new string('A', 201),
            CollectionId = 1
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateItemRequest_ValidWithProperName()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "My Item",
            CollectionId = 1
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void UpdateItemRequest_RequiresName()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "",
            CollectionId = 1
        };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    #endregion

    #region ItemTemplateRequests Tests

    [Fact]
    public void CreateItemTemplateRequest_RequiresName()
    {
        // Arrange
        var request = new CreateItemTemplateRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void CreateItemTemplateRequest_ValidatesNameMaxLength()
    {
        // Arrange
        var request = new CreateItemTemplateRequest { Name = new string('A', 201) };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    [Fact]
    public void UpdateItemTemplateRequest_RequiresName()
    {
        // Arrange
        var request = new UpdateItemTemplateRequest { Name = "" };

        // Act
        var results = ValidateModel(request);

        // Assert
        Assert.Contains(results, r => r.MemberNames.Contains("Name"));
    }

    #endregion
}
