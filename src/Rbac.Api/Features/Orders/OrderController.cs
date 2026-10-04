using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rbac.Api.Authorization;
using Rbac.Api.Data;
using Rbac.Api.Data.Entities;

namespace Rbac.Api.Features.Orders;

[ApiController]
[Route("orders")]
[Tags("Orders")]
public sealed class OrderController(RbacDbContext dbContext) : RbacControllerBase
{
    /// <summary>Lists orders. Requires orders:read.</summary>
    [HttpGet]
    [Authorize(Policy = Permissions.OrdersRead)]
    [EndpointSummary("Lists orders. Requires orders:read.")]
    [ProducesResponseType<OrderResponse[]>(StatusCodes.Status200OK)]
    public async Task<ActionResult<OrderResponse[]>> ListAsync(
        [FromQuery] OrderStatus? status,
        CancellationToken cancellationToken)
    {
        IQueryable<Order> query = dbContext.Orders.AsNoTracking();

        if (status is { } statusFilter)
        {
            query = query.Where(order => order.Status == statusFilter);
        }

        Order[] orders = await query.OrderByDescending(order => order.CreatedAt).ToArrayAsync(cancellationToken);

        OrderResponse[] response = [.. orders.Select(ToResponse)];

        return Ok(response);
    }

    /// <summary>Gets an order. Requires orders:read.</summary>
    [HttpGet("{id:int}")]
    [Authorize(Policy = Permissions.OrdersRead)]
    [EndpointSummary("Gets an order. Requires orders:read.")]
    [ProducesResponseType<OrderResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<OrderResponse>> GetAsync(int id, CancellationToken cancellationToken)
    {
        Order? order = await dbContext.Orders.AsNoTracking().FirstOrDefaultAsync(o => o.Id == id, cancellationToken);

        return order is null
            ? Problem(title: "Order not found", detail: $"No order with id {id}.", statusCode: StatusCodes.Status404NotFound)
            : Ok(ToResponse(order));
    }

    /// <summary>Creates an order. Requires orders:create.</summary>
    [HttpPost]
    [Authorize(Policy = Permissions.OrdersCreate)]
    [EndpointSummary("Creates an order. Requires orders:create.")]
    [ProducesResponseType<OrderResponse>(StatusCodes.Status201Created)]
    public async Task<ActionResult<OrderResponse>> CreateAsync(
        [FromBody] CreateOrderRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.CustomerEmail)
            || string.IsNullOrWhiteSpace(request.Description)
            || request.Total is null or <= 0)
        {
            return ValidationErrors(new Dictionary<string, string[]>
            {
                ["request"] = ["Customer email, description and a total greater than zero are required."]
            });
        }

        var order = new Order
        {
            CustomerEmail = request.CustomerEmail.Trim(),
            Description = request.Description.Trim(),
            Total = request.Total.Value,
            Status = OrderStatus.Placed,
            CreatedAt = DateTimeOffset.UtcNow
        };

        dbContext.Orders.Add(order);
        await dbContext.SaveChangesAsync(cancellationToken);

        return Created($"/orders/{order.Id}", ToResponse(order));
    }

    /// <summary>
    /// Cancels an order. Requires orders:cancel. Cancelling twice is a conflict, not a second success:
    /// the caller asked for a state change that has already happened.
    /// </summary>
    [HttpPost("{id:int}/cancel")]
    [Authorize(Policy = Permissions.OrdersCancel)]
    [EndpointSummary("Cancels an order. Requires orders:cancel.")]
    [ProducesResponseType<OrderResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<OrderResponse>> CancelAsync(int id, CancellationToken cancellationToken)
    {
        Order? order = await dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id, cancellationToken);

        if (order is null)
        {
            return Problem(title: "Order not found", detail: $"No order with id {id}.", statusCode: StatusCodes.Status404NotFound);
        }

        if (order.Status is OrderStatus.Cancelled)
        {
            return Problem(
                title: "Already cancelled",
                detail: $"Order {id} was already cancelled.",
                statusCode: StatusCodes.Status409Conflict);
        }

        order.Status = OrderStatus.Cancelled;
        order.CancelledAt = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);

        return Ok(ToResponse(order));
    }

    private static OrderResponse ToResponse(Order order) => new(
        order.Id,
        order.CustomerEmail,
        order.Description,
        order.Total,
        order.Status.ToString(),
        order.CreatedAt);
}
