using Rbac.Api.Configuration;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddRbacOpenApi();
builder.Services.AddRbacAuthentication(builder.Configuration);
builder.Services.AddRbacAuthorization(builder.Configuration);
builder.Services.AddRbacData(builder.Configuration);

WebApplication app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Order matters: authentication populates the principal, authorization evaluates the policies.
app.UseAuthentication();
app.UseAuthorization();

// Every action lives on a controller in Features/. The permission each one needs is declared on the
// action itself with [Authorize(Policy = Permissions.X)], so there is no endpoint mapping table to
// keep in sync.
app.MapControllers();

app.Run();

/// <summary>Exposed so the integration tests can boot this exact app through WebApplicationFactory.</summary>
public partial class Program;
