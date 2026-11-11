using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class RememberWelcomeCollection : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "WelcomeCollectionId",
                table: "Workspaces",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Workspaces_WelcomeCollectionId",
                table: "Workspaces",
                column: "WelcomeCollectionId");

            migrationBuilder.AddForeignKey(
                name: "FK_Workspaces_Collections_WelcomeCollectionId",
                table: "Workspaces",
                column: "WelcomeCollectionId",
                principalTable: "Collections",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Workspaces_Collections_WelcomeCollectionId",
                table: "Workspaces");

            migrationBuilder.DropIndex(
                name: "IX_Workspaces_WelcomeCollectionId",
                table: "Workspaces");

            migrationBuilder.DropColumn(
                name: "WelcomeCollectionId",
                table: "Workspaces");
        }
    }
}
