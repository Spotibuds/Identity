using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Migrations
{
    /// <inheritdoc />
    public partial class BrowserCookieHandoff : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsPending",
                table: "RefreshTokens",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "OperationHash",
                table: "RefreshTokens",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "PreparationExpiresAt",
                table: "RefreshTokens",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "PreparedFromId",
                table: "RefreshTokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_IsPending_PreparationExpiresAt",
                table: "RefreshTokens",
                columns: new[] { "IsPending", "PreparationExpiresAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_IsPending_PreparationExpiresAt",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "IsPending",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "OperationHash",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "PreparationExpiresAt",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "PreparedFromId",
                table: "RefreshTokens");
        }
    }
}
