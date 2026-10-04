namespace Rbac.Api.Features.Reports;

public sealed record ReportSummaryResponse(
    int TotalOrders,
    decimal TotalRevenue,
    int OrdersByStatusCount,
    IReadOnlyDictionary<string, int> OrdersByStatus,
    IReadOnlyDictionary<string, decimal> RevenueByStatus);
