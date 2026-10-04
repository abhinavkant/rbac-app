using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Rbac.Api.Features;

/// <summary>
/// The one thing every controller in this app needs in common: a 400 that says which field was wrong.
/// </summary>
public abstract class RbacControllerBase : ControllerBase
{
    /// <summary>
    /// A 400 carrying an RFC 7807 body with one or more errors per field, for example
    /// <c>["roles"] = ["Unknown role(s): Wizard."]</c>.
    /// <para>
    /// MVC only offers <c>ValidationProblem</c> overloads for a
    /// <see cref="Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary"/> or a ready-made
    /// <see cref="ValidationProblemDetails"/>, so this keeps the call sites to one line and the error keys
    /// ("roles", "permissions", "request") where the action can choose them instead of deriving them from
    /// property paths.
    /// </para>
    /// <para>
    /// The <c>type</c>, <c>title</c> and <c>traceId</c> are filled in from the same framework defaults that
    /// <c>[ApiController]</c>'s own model-binding errors use, so a 400 an action returns is indistinguishable
    /// from one the framework rejects the request with.
    /// </para>
    /// </summary>
    protected ActionResult ValidationErrors(IDictionary<string, string[]> errors)
    {
        // Applies the ProblemDetailsDefaults entry for 400, which supplies the RFC 9110 type URI. The title
        // stays whatever ValidationProblemDetails chose ("One or more validation errors occurred.").
        ProblemDetailsFactory factory = HttpContext.RequestServices.GetRequiredService<ProblemDetailsFactory>();
        ProblemDetails defaults = factory.CreateProblemDetails(HttpContext, StatusCodes.Status400BadRequest);

        var details = new ValidationProblemDetails(errors)
        {
            Status = StatusCodes.Status400BadRequest,
            Type = defaults.Type
        };

        details.Extensions["traceId"] = Activity.Current?.Id ?? HttpContext.TraceIdentifier;

        return ValidationProblem(details);
    }
}
