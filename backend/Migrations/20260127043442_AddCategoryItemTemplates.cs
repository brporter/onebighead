using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace backend.Migrations
{
    /// <inheritdoc />
    public partial class AddCategoryItemTemplates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CategoryItemTemplates",
                columns: table => new
                {
                    CategoryId = table.Column<int>(type: "int", nullable: false),
                    ItemTemplateId = table.Column<int>(type: "int", nullable: false),
                    SortOrder = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CategoryItemTemplates", x => new { x.CategoryId, x.ItemTemplateId });
                    table.ForeignKey(
                        name: "FK_CategoryItemTemplates_Categories_CategoryId",
                        column: x => x.CategoryId,
                        principalTable: "Categories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CategoryItemTemplates_ItemTemplates_ItemTemplateId",
                        column: x => x.ItemTemplateId,
                        principalTable: "ItemTemplates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CategoryItemTemplates_CategoryId",
                table: "CategoryItemTemplates",
                column: "CategoryId");

            migrationBuilder.CreateIndex(
                name: "IX_CategoryItemTemplates_ItemTemplateId",
                table: "CategoryItemTemplates",
                column: "ItemTemplateId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CategoryItemTemplates");
        }
    }
}
