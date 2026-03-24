using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class SimplifyVisibility : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Resolve Default (0) visibility values
            // Items: inherit from category, then collection
            migrationBuilder.Sql(@"
                UPDATE i SET i.Visibility =
                    CASE
                        WHEN c.Visibility = 2 THEN 2  -- Category is Public
                        WHEN col.Visibility = 2 THEN 2  -- Collection is Public
                        ELSE 1  -- Private
                    END
                FROM Items i
                LEFT JOIN Categories c ON i.CategoryId = c.Id
                LEFT JOIN Collections col ON i.CollectionId = col.Id
                WHERE i.Visibility = 0
            ");

            // Handle deeply nested categories with a recursive CTE
            migrationBuilder.Sql(@"
                ;WITH ResolvedCategories AS (
                    -- Base case: root categories (no parent) inherit from collection
                    SELECT cat.Id, cat.CollectionId, cat.ParentCategoryId,
                        CASE WHEN col.Visibility = 2 THEN 2 ELSE 1 END AS ResolvedVisibility
                    FROM Categories cat
                    INNER JOIN Collections col ON cat.CollectionId = col.Id
                    WHERE cat.ParentCategoryId IS NULL AND cat.Visibility = 0

                    UNION ALL

                    -- Recursive case: child categories inherit from resolved parent
                    SELECT child.Id, child.CollectionId, child.ParentCategoryId,
                        CASE WHEN parent.ResolvedVisibility = 2 THEN 2 ELSE 1 END AS ResolvedVisibility
                    FROM Categories child
                    INNER JOIN ResolvedCategories parent ON child.ParentCategoryId = parent.Id
                    WHERE child.Visibility = 0
                )
                UPDATE cat SET cat.Visibility = rc.ResolvedVisibility
                FROM Categories cat
                INNER JOIN ResolvedCategories rc ON cat.Id = rc.Id
            ");

            // Remaining Default values become Private (safety net)
            migrationBuilder.Sql("UPDATE Items SET Visibility = 1 WHERE Visibility = 0");
            migrationBuilder.Sql("UPDATE Categories SET Visibility = 1 WHERE Visibility = 0");

            migrationBuilder.DropColumn(
                name: "IsPublicAccessEnabled",
                table: "Workspaces");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsPublicAccessEnabled",
                table: "Workspaces",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }
    }
}
