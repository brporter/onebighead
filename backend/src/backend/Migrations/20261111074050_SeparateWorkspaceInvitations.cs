using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class SeparateWorkspaceInvitations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "WorkspaceInvitations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    WorkspaceId = table.Column<int>(type: "integer", nullable: false),
                    Email = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    Role = table.Column<int>(type: "integer", nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AcceptedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AcceptedByUserId = table.Column<int>(type: "integer", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkspaceInvitations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_WorkspaceInvitations_Users_AcceptedByUserId",
                        column: x => x.AcceptedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_WorkspaceInvitations_Workspaces_WorkspaceId",
                        column: x => x.WorkspaceId,
                        principalTable: "Workspaces",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceInvitations_AcceptedByUserId",
                table: "WorkspaceInvitations",
                column: "AcceptedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceInvitations_WorkspaceId_Email",
                table: "WorkspaceInvitations",
                columns: new[] { "WorkspaceId", "Email" },
                unique: true,
                filter: "\"AcceptedAt\" IS NULL");

            // Preserve legacy pending invitations as expired grants requiring an administrator to issue a link.
            // Accounts and their history remain; unclaimed placeholders no longer count as workspace members.
            migrationBuilder.Sql("""
                INSERT INTO "WorkspaceInvitations" ("Id", "WorkspaceId", "Email", "Role", "TokenHash", "CreatedAt", "ExpiresAt")
                SELECT gen_random_uuid(), membership."WorkspaceId", LOWER(account."Email"), MIN(membership."WorkspaceRole"),
                    repeat('0', 64), MIN(membership."CreatedAt"), CURRENT_TIMESTAMP - INTERVAL '1 second'
                FROM "WorkspaceUsers" AS membership JOIN "Users" AS account ON account."Id" = membership."UserId"
                WHERE account."ProviderSubjectId" IS NULL OR account."ProviderSubjectId" = ''
                GROUP BY membership."WorkspaceId", LOWER(account."Email")
                """);
            migrationBuilder.Sql("""
                DELETE FROM "WorkspaceUsers" AS membership USING "Users" AS account
                WHERE membership."UserId" = account."Id" AND (account."ProviderSubjectId" IS NULL OR account."ProviderSubjectId" = '')
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "WorkspaceInvitations");
        }
    }
}
