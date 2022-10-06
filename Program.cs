using aspnetcore_2fa_redirect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDataContext>(options => options.UseSqlite("DataSource=mydatabase.db;"));
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddDefaultTokenProviders()
    .AddEntityFrameworkStores<ApplicationDataContext>();
builder.Services.AddAuthorization();

// This code fixes problem.
/*builder.Services.Configure<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme,
    c =>
    {
        c.LoginPath = "/some-path-which-not-exist";
        // ... or ...
        //c.Events.OnRedirectToReturnUrl = _ => Task.CompletedTask;
    });
*/

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Main page.
app.MapGet("/", [Authorize] async (context) =>
{
    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync("<a href='/Account/Login'>Sign in</a>");
});

// Sign-in page.
app.MapGet("/Account/Login", [AllowAnonymous] async (HttpContext context, SignInManager<IdentityUser> signInManager) =>
{
    var user = await signInManager.UserManager.FindByNameAsync("userName");
    if (user == default)
    {
        user = await CreateTextUserAsync(signInManager.UserManager);
    }
    var signInResult = await signInManager.PasswordSignInAsync(user, "Pa$$w0rd", isPersistent: true, lockoutOnFailure: true);
    if (signInResult.RequiresTwoFactor)
    {
        // Some logic, ex. logging or processing session.
        // Something went wrong and current Razor Page or View shoud be shown, but...
        if (context.Response.StatusCode == 302)
        {
            throw new Exception("Redirect to ReturnUrl!"); // !!!
        }
    }
    await context.Response.WriteAsync("There is no redirection!");
});

app.Run();

/// <summary>
/// Creates test user with 2FA.
/// </summary>
async Task<IdentityUser> CreateTextUserAsync(UserManager<IdentityUser> userManager)
{
    IdentityUser user = new();
    await userManager.SetUserNameAsync(user, "userName");
    await userManager.SetEmailAsync(user, "email@example.com");
    await userManager.SetTwoFactorEnabledAsync(user, true);
    var creationResult = await userManager.CreateAsync(user, "Pa$$w0rd");
    if (!creationResult.Succeeded)
    {
        throw new Exception("user creation error");
    }
    var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
    await userManager.ConfirmEmailAsync(user, token);
    return user;
}
