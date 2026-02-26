using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddItemMatching : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ItemEmbeddings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ItemId = table.Column<int>(type: "int", nullable: false),
                    WorkspaceId = table.Column<int>(type: "int", nullable: false),
                    Vector = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ContentHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ItemEmbeddings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ItemMatches",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    WantItemId = table.Column<int>(type: "int", nullable: false),
                    WantWorkspaceId = table.Column<int>(type: "int", nullable: false),
                    TradeItemId = table.Column<int>(type: "int", nullable: false),
                    TradeWorkspaceId = table.Column<int>(type: "int", nullable: false),
                    ConfidenceScore = table.Column<double>(type: "float", nullable: false),
                    MatchReason = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: false),
                    WantUserStatus = table.Column<int>(type: "int", nullable: false),
                    TradeUserStatus = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ItemMatches", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MatchQueueEntries",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ItemId = table.Column<int>(type: "int", nullable: false),
                    WorkspaceId = table.Column<int>(type: "int", nullable: false),
                    Reason = table.Column<int>(type: "int", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    EnqueuedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ProcessedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ErrorMessage = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: true),
                    RetryCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MatchQueueEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MatchMessages",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ItemMatchId = table.Column<int>(type: "int", nullable: false),
                    SenderUserId = table.Column<int>(type: "int", nullable: false),
                    SenderWorkspaceId = table.Column<int>(type: "int", nullable: false),
                    Message = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: false),
                    IsRead = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MatchMessages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MatchMessages_ItemMatches_ItemMatchId",
                        column: x => x.ItemMatchId,
                        principalTable: "ItemMatches",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ItemEmbeddings_ItemId",
                table: "ItemEmbeddings",
                column: "ItemId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ItemEmbeddings_WorkspaceId_ItemId",
                table: "ItemEmbeddings",
                columns: new[] { "WorkspaceId", "ItemId" });

            migrationBuilder.CreateIndex(
                name: "IX_ItemMatches_TradeWorkspaceId",
                table: "ItemMatches",
                column: "TradeWorkspaceId");

            migrationBuilder.CreateIndex(
                name: "IX_ItemMatches_WantItemId_TradeItemId",
                table: "ItemMatches",
                columns: new[] { "WantItemId", "TradeItemId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ItemMatches_WantWorkspaceId",
                table: "ItemMatches",
                column: "WantWorkspaceId");

            migrationBuilder.CreateIndex(
                name: "IX_MatchMessages_ItemMatchId",
                table: "MatchMessages",
                column: "ItemMatchId");

            migrationBuilder.CreateIndex(
                name: "IX_MatchMessages_ItemMatchId_CreatedAt",
                table: "MatchMessages",
                columns: new[] { "ItemMatchId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_MatchQueueEntries_ItemId",
                table: "MatchQueueEntries",
                column: "ItemId");

            migrationBuilder.CreateIndex(
                name: "IX_MatchQueueEntries_Status_EnqueuedAt",
                table: "MatchQueueEntries",
                columns: new[] { "Status", "EnqueuedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ItemEmbeddings");

            migrationBuilder.DropTable(
                name: "MatchMessages");

            migrationBuilder.DropTable(
                name: "MatchQueueEntries");

            migrationBuilder.DropTable(
                name: "ItemMatches");
        }
    }
}
