using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Migrations
{
    /// <inheritdoc />
    public partial class ImmutableProfileOutbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ProfileSyncWork_UserId_Delete",
                table: "ProfileSyncWork");

            migrationBuilder.CreateIndex(
                name: "IX_ProfileSyncWork_UserId_Delete",
                table: "ProfileSyncWork",
                columns: new[] { "UserId", "Delete" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ProfileSyncWork_UserId_Delete",
                table: "ProfileSyncWork");

            migrationBuilder.CreateIndex(
                name: "IX_ProfileSyncWork_UserId_Delete",
                table: "ProfileSyncWork",
                columns: new[] { "UserId", "Delete" },
                unique: true);
        }
    }
}
