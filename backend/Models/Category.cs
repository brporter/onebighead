﻿﻿﻿using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace backend.Models;

public class Category
{
    [Key]
    [JsonPropertyName("categoryId")]
    public int Id { get; set; }

    public int TenantId { get; set; }

    public int CollectionId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public bool IsSystem { get; set; } = false;

    public int? ParentCategoryId { get; set; }

    [JsonPropertyName("isPublicOverride")]
    public bool? IsPublicOverride { get; set; }

    [NotMapped]
    [JsonPropertyName("effectiveIsPublic")]
    public bool EffectiveIsPublic { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(ParentCategoryId))]
    public Category? ParentCategory { get; set; }

    [JsonIgnore]
    public ICollection<Category> ChildCategories { get; set; } = new List<Category>();

    [JsonIgnore]
    [ForeignKey(nameof(TenantId))]
    public Tenant? Tenant { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(CollectionId))]
    public Collection? Collection { get; set; }

    [JsonIgnore]
    public ICollection<CategoryItemTemplate> CategoryItemTemplates { get; set; } = new List<CategoryItemTemplate>();
}

