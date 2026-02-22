using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCollectionStatistics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "CreatedAt",
                table: "Items",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.CreateTable(
                name: "CollectionItemHighlights",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CollectionId = table.Column<int>(type: "int", nullable: false),
                    ItemId = table.Column<int>(type: "int", nullable: false),
                    ViewCount = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CollectionItemHighlights", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CollectionItemHighlights_Items_ItemId",
                        column: x => x.ItemId,
                        principalTable: "Items",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CollectionStatistics",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CollectionId = table.Column<int>(type: "int", nullable: false),
                    StatisticType = table.Column<int>(type: "int", nullable: false),
                    Value = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CollectionStatistics", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Items_CollectionId_CreatedAt",
                table: "Items",
                columns: new[] { "CollectionId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_CollectionItemHighlights_CollectionId_ItemId",
                table: "CollectionItemHighlights",
                columns: new[] { "CollectionId", "ItemId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CollectionItemHighlights_CollectionId_ViewCount",
                table: "CollectionItemHighlights",
                columns: new[] { "CollectionId", "ViewCount" });

            migrationBuilder.CreateIndex(
                name: "IX_CollectionItemHighlights_ItemId",
                table: "CollectionItemHighlights",
                column: "ItemId");

            migrationBuilder.CreateIndex(
                name: "IX_CollectionStatistics_CollectionId",
                table: "CollectionStatistics",
                column: "CollectionId");

            migrationBuilder.CreateIndex(
                name: "IX_CollectionStatistics_CollectionId_StatisticType",
                table: "CollectionStatistics",
                columns: new[] { "CollectionId", "StatisticType" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CollectionItemHighlights");

            migrationBuilder.DropTable(
                name: "CollectionStatistics");

            migrationBuilder.DropIndex(
                name: "IX_Items_CollectionId_CreatedAt",
                table: "Items");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "Items");
        }
    }
}
