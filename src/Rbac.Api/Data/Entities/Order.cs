using System.ComponentModel.DataAnnotations;

namespace Rbac.Api.Data.Entities;

public class Order
{
    public int Id { get; set; }

    [MaxLength(320)]
    public required string CustomerEmail { get; set; }

    [MaxLength(100)]
    public required string Description { get; set; }

    public decimal Total { get; set; }

    public OrderStatus Status { get; set; } = OrderStatus.Placed;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? CancelledAt { get; set; }
}

public enum OrderStatus
{
    Placed = 0,
    Shipped = 1,
    Delivered = 2,
    Cancelled = 3
}
