using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Rbac.Api.Authorization;

namespace Rbac.Api.Security;

/// <summary>
/// Returns 401 and 403 as RFC 7807 problem documents. Out of the box ASP.NET Core answers those
/// with an empty body, which makes debugging "why was I rejected?" needlessly painful.
/// </summary>
public sealed class RbacJwtBearerEvents : JwtBearerEvents
{
    public override Task Challenge(JwtBearerChallengeContext context)
    {
        // Stop the default handler from writing an empty 401 body.
        context.HandleResponse();

        // The default JwtBearerEvents implementation writes this header, so an override has to keep
        // it: clients (and RFC 6750) expect a challenge on a 401.
        context.Response.Headers.Append(HeaderNames.WWWAuthenticate, "Bearer");

        string detail = context.AuthenticateFailure switch
        {
            SecurityTokenExpiredException => "The access token has expired. Sign in again to get a new one.",
            SecurityTokenException => "The access token is not valid.",
            _ => "This endpoint requires a valid bearer token. Send 'Authorization: Bearer <token>'."
        };

        return WriteProblemAsync(
            context.HttpContext,
            StatusCodes.Status401Unauthorized,
            title: "Unauthorized",
            detail: detail,
            grantedPermissions: null);
    }

    public override Task Forbidden(ForbiddenContext context)
    {
        // The token is fine, the caller simply lacks the permission. Say which ones they do have.
        return WriteProblemAsync(
            context.HttpContext,
            StatusCodes.Status403Forbidden,
            title: "Forbidden",
            detail: "You are authenticated, but you do not have the permission required by this endpoint.",
            grantedPermissions: context.HttpContext.User.GetPermissions());
    }

    private static Task WriteProblemAsync(
        HttpContext httpContext,
        int statusCode,
        string title,
        string detail,
        IReadOnlyList<string>? grantedPermissions)
    {
        var extensions = new Dictionary<string, object?>
        {
            ["traceId"] = httpContext.TraceIdentifier
        };

        if (grantedPermissions is { Count: > 0 })
        {
            extensions["grantedPermissions"] = grantedPermissions;
        }

        httpContext.Response.StatusCode = statusCode;

        return TypedResults
            .Problem(statusCode: statusCode, title: title, detail: detail, extensions: extensions)
            .ExecuteAsync(httpContext);
    }
}
