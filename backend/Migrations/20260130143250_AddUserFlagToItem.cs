using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace backend.Migrations
{
    /// <inheritdoc />
    public partial class AddUserFlagToItem : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "UserFlag",
                table: "Items",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_Items_TenantId_UserFlag",
                table: "Items",
                columns: new[] { "TenantId", "UserFlag" });

            migrationBuilder.CreateIndex(
                name: "IX_Items_UserFlag",
                table: "Items",
                column: "UserFlag");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Items_TenantId_UserFlag",
                table: "Items");

            migrationBuilder.DropIndex(
                name: "IX_Items_UserFlag",
                table: "Items");

            migrationBuilder.DropColumn(
                name: "UserFlag",
                table: "Items");
        }
    }
}
