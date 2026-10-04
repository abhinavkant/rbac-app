using Microsoft.OpenApi;

namespace Rbac.Api.Configuration;

public static class OpenApiExtensions
{
    public static IServiceCollection AddRbacOpenApi(this IServiceCollection services)
    {
        return services.AddOpenApi("v1", options =>
        {
            options.AddDocumentTransformer((document, _, _) =>
            {
                document.Info = new OpenApiInfo
                {
                    Title = "RBAC sample API",
                    Version = "v1",
                    Description =
                        "Permission-based RBAC sample. Sign in at POST /auth/login, then send the returned " +
                        "token as 'Authorization: Bearer <token>'. Every endpoint requires a permission, " +
                        "not a role - 403 means the token is valid but lacks the permission."
                };

                OpenApiComponents components = document.Components ??= new OpenApiComponents();
                components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
                components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Paste the access token returned by /auth/login."
                };

                return Task.CompletedTask;
            });
        });
    }
}
