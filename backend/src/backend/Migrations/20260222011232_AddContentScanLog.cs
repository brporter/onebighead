using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddContentScanLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ContentScanLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkspaceId = table.Column<int>(type: "int", nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: true),
                    ScannerName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsMatch = table.Column<bool>(type: "bit", nullable: false),
                    MatchScore = table.Column<double>(type: "float", nullable: false),
                    Details = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    OriginalFileName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ContentType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    FileSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    ImageHash = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ScannedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ReportSubmitted = table.Column<bool>(type: "bit", nullable: false),
                    ReportedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ContentScanLogs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ContentScanLogs_IsMatch",
                table: "ContentScanLogs",
                column: "IsMatch");

            migrationBuilder.CreateIndex(
                name: "IX_ContentScanLogs_ScannedAt",
                table: "ContentScanLogs",
                column: "ScannedAt");

            migrationBuilder.CreateIndex(
                name: "IX_ContentScanLogs_WorkspaceId",
                table: "ContentScanLogs",
                column: "WorkspaceId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ContentScanLogs");
        }
    }
}
