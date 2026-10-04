using Rbac.Api.Data.Entities;

namespace Rbac.Api.Features.Orders;

public sealed record OrderResponse(
    int Id,
    string CustomerEmail,
    string Description,
    decimal Total,
    string Status,
    DateTimeOffset CreatedAt);

public sealed record CreateOrderRequest(string? CustomerEmail, string? Description, decimal? Total);
