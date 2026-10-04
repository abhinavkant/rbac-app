using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;

namespace Rbac.Api.Features.Reports;

/// <summary>
/// Three adjacent actions with three different permissions - the classic RBAC demonstration: a Manager
/// can look at the summary, but only an Administrator (or the Viewer with a direct grant) may export the
/// data, and the combined report needs both permissions at once.
/// </summary>
[ApiController]
[Route("reports")]
[Tags("Reports")]
public sealed class ReportController(RbacDbContext dbContext) : RbacControllerBase
{
    /// <summary>Aggregated numbers. Requires reports:read.</summary>
    [HttpGet("summary")]
    [Authorize(Policy = Permissions.ReportsRead)]
    [EndpointSummary("Aggregated numbers. Requires reports:read.")]
    [ProducesResponseType<ReportSummaryResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<ReportSummaryResponse>> SummaryAsync(CancellationToken cancellationToken)
    {
        Order[] orders = await dbContext.Orders.AsNoTracking().ToArrayAsync(cancellationToken);

        return Ok(new ReportSummaryResponse(
            orders.Length,
            orders.Where(order => order.Status is not OrderStatus.Cancelled).Sum(order => order.Total),
            orders.Length,
            orders.GroupBy(order => order.Status).ToDictionary(group => group.Key.ToString(), group => group.Count()),
            orders.GroupBy(order => order.Status).ToDictionary(group => group.Key.ToString(), group => group.Sum(order => order.Total))));
    }

    /// <summary>Downloads the raw orders as CSV. Requires reports:export.</summary>
    [HttpGet("export")]
    [Authorize(Policy = Permissions.ReportsExport)]
    [EndpointSummary("Downloads the raw orders as CSV. Requires reports:export.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Export()
    {
        Order[] orders = dbContext.Orders.AsNoTracking().OrderBy(order => order.Id).ToArray();

        // The byte[] overload so the response carries a Content-Disposition download header.
        return File(Encoding.UTF8.GetBytes(BuildCsv(orders)), "text/csv", "orders.csv");
    }

    /// <summary>Summary and export in one call. Requires reports:read and reports:export.</summary>
    [HttpGet("full")]
    [Authorize(Policy = PermissionPolicies.ReportsReadAndExport)]
    [EndpointSummary("Summary and export in one call. Requires reports:read and reports:export.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> FullReportAsync(CancellationToken cancellationToken)
    {
        Order[] orders = await dbContext.Orders.AsNoTracking().OrderBy(order => order.Id).ToArrayAsync(cancellationToken);

        return Ok(new
        {
            summary = new
            {
                totalOrders = orders.Length,
                revenue = orders.Where(order => order.Status is not OrderStatus.Cancelled).Sum(order => order.Total)
            },
            orders = orders.Select(order => new
            {
                order.Id,
                order.CustomerEmail,
                order.Description,
                order.Total,
                status = order.Status.ToString(),
                order.CreatedAt
            })
        });
    }

    private static string BuildCsv(Order[] orders)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Id,CustomerEmail,Description,Total,Status,CreatedAt");

        foreach (Order order in orders)
        {
            builder.Append(order.Id).Append(',')
                .Append(order.CustomerEmail).Append(',')
                .Append('"').Append(order.Description.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"').Append(',')
                .Append(order.Total.ToString("0.00", CultureInfo.InvariantCulture)).Append(',')
                .Append(order.Status).Append(',')
                .AppendLine(order.CreatedAt.ToString("O", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}
