using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCollectionThemes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CollectionThemes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    IconName = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    SortOrder = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CollectionThemes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CollectionThemeCategories",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThemeId = table.Column<int>(type: "int", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: false),
                    ParentName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    SortOrder = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CollectionThemeCategories", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CollectionThemeCategories_CollectionThemes_ThemeId",
                        column: x => x.ThemeId,
                        principalTable: "CollectionThemes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CollectionThemeTemplates",
                columns: table => new
                {
                    ThemeId = table.Column<int>(type: "int", nullable: false),
                    ItemTemplateId = table.Column<int>(type: "int", nullable: false),
                    SortOrder = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CollectionThemeTemplates", x => new { x.ThemeId, x.ItemTemplateId });
                    table.ForeignKey(
                        name: "FK_CollectionThemeTemplates_CollectionThemes_ThemeId",
                        column: x => x.ThemeId,
                        principalTable: "CollectionThemes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CollectionThemeTemplates_ItemTemplates_ItemTemplateId",
                        column: x => x.ItemTemplateId,
                        principalTable: "ItemTemplates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CollectionThemeCategories_ThemeId",
                table: "CollectionThemeCategories",
                column: "ThemeId");

            migrationBuilder.CreateIndex(
                name: "IX_CollectionThemes_SortOrder",
                table: "CollectionThemes",
                column: "SortOrder");

            migrationBuilder.CreateIndex(
                name: "IX_CollectionThemeTemplates_ItemTemplateId",
                table: "CollectionThemeTemplates",
                column: "ItemTemplateId");

            migrationBuilder.CreateIndex(
                name: "IX_CollectionThemeTemplates_ThemeId",
                table: "CollectionThemeTemplates",
                column: "ThemeId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CollectionThemeCategories");

            migrationBuilder.DropTable(
                name: "CollectionThemeTemplates");

            migrationBuilder.DropTable(
                name: "CollectionThemes");
        }
    }
}
