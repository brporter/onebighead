using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class CollectionItemTemplate
{
    public int CollectionId { get; set; }

    public int ItemTemplateId { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(CollectionId))]
    public Collection? Collection { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(ItemTemplateId))]
    public ItemTemplate? ItemTemplate { get; set; }
}
