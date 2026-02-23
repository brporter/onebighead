using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class CollectionItemHighlight
{
    public int Id { get; set; }
    public int CollectionId { get; set; }
    public int ItemId { get; set; }
    public long ViewCount { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(ItemId))]
    public Item? Item { get; set; }
}
