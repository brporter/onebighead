using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OneBigHead.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddWorkspaceStatistics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "WorkspaceStatistics",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    WorkspaceId = table.Column<int>(type: "int", nullable: false),
                    StatisticType = table.Column<int>(type: "int", nullable: false),
                    Date = table.Column<DateOnly>(type: "date", nullable: false),
                    Value = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkspaceStatistics", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceStatistics_WorkspaceId",
                table: "WorkspaceStatistics",
                column: "WorkspaceId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceStatistics_WorkspaceId_StatisticType_Date",
                table: "WorkspaceStatistics",
                columns: new[] { "WorkspaceId", "StatisticType", "Date" },
                unique: true);

            // Seed aggregate stats from existing data
            migrationBuilder.Sql(@"
                INSERT INTO WorkspaceStatistics (WorkspaceId, StatisticType, Date, Value)
                SELECT WorkspaceId, 1, '0001-01-01', COUNT(*)
                FROM Collections GROUP BY WorkspaceId;

                INSERT INTO WorkspaceStatistics (WorkspaceId, StatisticType, Date, Value)
                SELECT WorkspaceId, 2, '0001-01-01', COUNT(*)
                FROM Items GROUP BY WorkspaceId;

                INSERT INTO WorkspaceStatistics (WorkspaceId, StatisticType, Date, Value)
                SELECT WorkspaceId, 3, '0001-01-01', COUNT(*)
                FROM StoredImages GROUP BY WorkspaceId;

                INSERT INTO WorkspaceStatistics (WorkspaceId, StatisticType, Date, Value)
                SELECT WorkspaceId, 4, '0001-01-01', SUM(CAST(DATALENGTH(Data) AS bigint))
                FROM StoredImages GROUP BY WorkspaceId;
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "WorkspaceStatistics");
        }
    }
}
