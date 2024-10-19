
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace IPWhitelistMiddleware.Middlewares
{
    public class IPWhitelistMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;

        public IPWhitelistMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var remoteIp = context.Connection.RemoteIpAddress;
            var allowedIPs = _configuration.GetSection("AllowedIPs").Get<string[]>();

            if (!IPAddress.IsLoopback(remoteIp) && !allowedIPs.Contains(remoteIp?.ToString()))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                await context.Response.WriteAsync("Access denied for IP: " + remoteIp);
                return;
            }

            await _next(context);
        }
    }
}
