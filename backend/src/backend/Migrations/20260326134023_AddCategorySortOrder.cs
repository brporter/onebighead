using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCategorySortOrder : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "SortOrder",
                table: "Categories",
                type: "int",
                nullable: false,
                defaultValue: 0);

            // Seed default sort orders: alphabetical within each parent group.
            // Wrapped in EXEC so the UPDATE is compiled at execution time, after the
            // ALTER TABLE above has added the SortOrder column. Without EXEC, the
            // idempotent deployment script emits ALTER + UPDATE in a single batch,
            // and SQL Server binds column references against existing tables at
            // batch-compile time, causing "Invalid column name 'SortOrder'".
            migrationBuilder.Sql(@"
                EXEC(N'
                    WITH Ranked AS (
                        SELECT Id, ROW_NUMBER() OVER (PARTITION BY ParentCategoryId, CollectionId ORDER BY Name) - 1 AS NewSort
                        FROM Categories
                    )
                    UPDATE c SET c.SortOrder = r.NewSort
                    FROM Categories c INNER JOIN Ranked r ON c.Id = r.Id
                ')
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SortOrder",
                table: "Categories");
        }
    }
}
