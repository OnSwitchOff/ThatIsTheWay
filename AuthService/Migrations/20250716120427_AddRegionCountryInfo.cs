using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthService.Migrations
{
    /// <inheritdoc />
    public partial class AddRegionCountryInfo : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: new Guid("a2cc15db-c7ea-46f0-95b3-5dc5a8604e6d"));

            migrationBuilder.AddColumn<string>(
                name: "Country",
                table: "LoginAttempts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Region",
                table: "LoginAttempts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "CreatedAt", "Email", "FullName", "MustChangePassword", "PasswordHash", "Role", "Username" },
                values: new object[] { new Guid("7dac0506-d58d-447c-a12c-0ddf3ebb72e6"), new DateTime(2025, 7, 16, 12, 4, 27, 102, DateTimeKind.Utc).AddTicks(7555), "admin@example.com", "Administrator", true, "$2a$11$fZCR6l0CNtCFag1yV30OueT0iNXBXPy/qL5Jb2VPKZHUNMHAzkbA.", "Admin", "admin" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: new Guid("7dac0506-d58d-447c-a12c-0ddf3ebb72e6"));

            migrationBuilder.DropColumn(
                name: "Country",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "Region",
                table: "LoginAttempts");

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "CreatedAt", "Email", "FullName", "MustChangePassword", "PasswordHash", "Role", "Username" },
                values: new object[] { new Guid("a2cc15db-c7ea-46f0-95b3-5dc5a8604e6d"), new DateTime(2025, 7, 16, 8, 6, 22, 877, DateTimeKind.Utc).AddTicks(4271), "admin@example.com", "Administrator", true, "$2a$11$BLNPMmJbQMwFktbDHJifnuARn61GJx8Bq0sOCOURuyo7ydS/yYmxK", "Admin", "admin" });
        }
    }
}
