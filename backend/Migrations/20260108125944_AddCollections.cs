using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace backend.Migrations
{
    /// <inheritdoc />
    public partial class AddCollections : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "CollectionId",
                table: "Items",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "CollectionId",
                table: "Categories",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "Collections",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TenantId = table.Column<int>(type: "INTEGER", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    HeroImageUrl = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    Slug = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Collections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Collections_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Items_CollectionId",
                table: "Items",
                column: "CollectionId");

            migrationBuilder.CreateIndex(
                name: "IX_Categories_CollectionId",
                table: "Categories",
                column: "CollectionId");

            migrationBuilder.CreateIndex(
                name: "IX_Collections_TenantId",
                table: "Collections",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Collections_TenantId_Slug",
                table: "Collections",
                columns: new[] { "TenantId", "Slug" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Categories_Collections_CollectionId",
                table: "Categories",
                column: "CollectionId",
                principalTable: "Collections",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Items_Collections_CollectionId",
                table: "Items",
                column: "CollectionId",
                principalTable: "Collections",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Categories_Collections_CollectionId",
                table: "Categories");

            migrationBuilder.DropForeignKey(
                name: "FK_Items_Collections_CollectionId",
                table: "Items");

            migrationBuilder.DropTable(
                name: "Collections");

            migrationBuilder.DropIndex(
                name: "IX_Items_CollectionId",
                table: "Items");

            migrationBuilder.DropIndex(
                name: "IX_Categories_CollectionId",
                table: "Categories");

            migrationBuilder.DropColumn(
                name: "CollectionId",
                table: "Items");

            migrationBuilder.DropColumn(
                name: "CollectionId",
                table: "Categories");
        }
    }
}
