using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddTenantRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_IdentityProvider_ProviderSubjectId",
                table: "Users");

            migrationBuilder.AlterColumn<string>(
                name: "ProviderSubjectId",
                table: "Users",
                type: "nvarchar(255)",
                maxLength: 255,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(255)",
                oldMaxLength: 255);

            migrationBuilder.AddColumn<int>(
                name: "TenantRole",
                table: "Users",
                type: "int",
                nullable: false,
                defaultValue: 0);

            // Set all existing users as TenantAdmin since they created their tenants
            // Use EXEC to defer parsing - otherwise SQL Server validates column names at batch compile time
            // before the ADD COLUMN has executed, causing "Invalid column name 'TenantRole'" error
            migrationBuilder.Sql("EXEC(N'UPDATE Users SET TenantRole = 1')");

            migrationBuilder.CreateIndex(
                name: "IX_Users_IdentityProvider_ProviderSubjectId",
                table: "Users",
                columns: new[] { "IdentityProvider", "ProviderSubjectId" },
                unique: true,
                filter: "[ProviderSubjectId] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_IdentityProvider_ProviderSubjectId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TenantRole",
                table: "Users");

            migrationBuilder.AlterColumn<string>(
                name: "ProviderSubjectId",
                table: "Users",
                type: "nvarchar(255)",
                maxLength: 255,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(255)",
                oldMaxLength: 255,
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_IdentityProvider_ProviderSubjectId",
                table: "Users",
                columns: new[] { "IdentityProvider", "ProviderSubjectId" },
                unique: true);
        }
    }
}
