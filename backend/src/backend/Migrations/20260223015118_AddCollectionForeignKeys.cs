using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCollectionForeignKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CollectionItemHighlights_Items_ItemId",
                table: "CollectionItemHighlights");

            migrationBuilder.AddForeignKey(
                name: "FK_CollectionItemHighlights_Collections_CollectionId",
                table: "CollectionItemHighlights",
                column: "CollectionId",
                principalTable: "Collections",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CollectionItemHighlights_Items_ItemId",
                table: "CollectionItemHighlights",
                column: "ItemId",
                principalTable: "Items",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_CollectionStatistics_Collections_CollectionId",
                table: "CollectionStatistics",
                column: "CollectionId",
                principalTable: "Collections",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CollectionItemHighlights_Collections_CollectionId",
                table: "CollectionItemHighlights");

            migrationBuilder.DropForeignKey(
                name: "FK_CollectionItemHighlights_Items_ItemId",
                table: "CollectionItemHighlights");

            migrationBuilder.DropForeignKey(
                name: "FK_CollectionStatistics_Collections_CollectionId",
                table: "CollectionStatistics");

            migrationBuilder.AddForeignKey(
                name: "FK_CollectionItemHighlights_Items_ItemId",
                table: "CollectionItemHighlights",
                column: "ItemId",
                principalTable: "Items",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
