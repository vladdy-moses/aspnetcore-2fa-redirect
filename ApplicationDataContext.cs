using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace aspnetcore_2fa_redirect;

/// <summary>
/// Application data context.
/// </summary>
public class ApplicationDataContext : IdentityDbContext
{
    public ApplicationDataContext(DbContextOptions options) : base(options)
    {
        Database.EnsureCreated();
    }
}
