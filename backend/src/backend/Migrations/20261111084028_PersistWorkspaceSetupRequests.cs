using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class PersistWorkspaceSetupRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "WorkspaceSetupReceipts",
                columns: table => new
                {
                    UserId = table.Column<int>(type: "integer", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    WorkspaceId = table.Column<int>(type: "integer", nullable: true),
                    CollectionId = table.Column<int>(type: "integer", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkspaceSetupReceipts", x => new { x.UserId, x.RequestId });
                    table.ForeignKey(
                        name: "FK_WorkspaceSetupReceipts_Collections_CollectionId",
                        column: x => x.CollectionId,
                        principalTable: "Collections",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_WorkspaceSetupReceipts_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_WorkspaceSetupReceipts_Workspaces_WorkspaceId",
                        column: x => x.WorkspaceId,
                        principalTable: "Workspaces",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceSetupReceipts_CollectionId",
                table: "WorkspaceSetupReceipts",
                column: "CollectionId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceSetupReceipts_WorkspaceId",
                table: "WorkspaceSetupReceipts",
                column: "WorkspaceId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "WorkspaceSetupReceipts");
        }
    }
}
