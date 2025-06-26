using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace NetworkDiagnostics
{
    /// <summary>
    /// Represents the immutable result of a single ping operation.
    /// </summary>
    public sealed class PingResult
    {
        /// <summary>
        /// Gets a value indicating whether the ping was successful.
        /// </summary>
        public bool IsSuccess => Status == IPStatus.Success;

        /// <summary>
        /// Gets the host name or IP address that was pinged.
        /// </summary>
        public string? Host { get; init; }

        /// <summary>
        /// Gets the IP address of the host that responded to the ping, if available.
        /// </summary>
        public IPAddress? Address { get; init; }

        /// <summary>
        /// Gets the round-trip time in milliseconds for the ping.
        /// </summary>
        public long RoundTripTime { get; init; }

        /// <summary>
        /// Gets the Time-To-Live (TTL) value of the ping response.
        /// </summary>
        public int TimeToLive { get; init; }

        /// <summary>
        /// Gets the status of the ping operation.
        /// </summary>
        public IPStatus Status { get; init; }

        /// <summary>
        /// Gets the error message if the ping failed, or null if successful.
        /// </summary>
        public string? ErrorMessage { get; init; }

        /// <summary>
        /// Returns a string representation of the ping result.
        /// </summary>
        /// <returns>A formatted string describing the ping outcome.</returns>
        public override string ToString()
        {
            if (IsSuccess && Address != null)
            {
                return $"Reply from {Host ?? Address.ToString()}: time={RoundTripTime}ms TTL={TimeToLive}";
            }
            return ErrorMessage ?? $"Ping to {Host ?? "unknown"} failed: {Status}";
        }
    }

    /// <summary>
    /// Represents a single, immutable hop in a traceroute operation.
    /// </summary>
    public sealed class TracerouteHop
    {
        /// <summary>
        /// Gets the hop number in the traceroute sequence.
        /// </summary>
        public int Hop { get; init; }

        /// <summary>
        /// Gets the IP address of the hop, if available.
        /// </summary>
        public IPAddress? Address { get; init; }

        /// <summary>
        /// Gets the round-trip time in milliseconds for the hop.
        /// </summary>
        public long RoundTripTime { get; init; }

        /// <summary>
        /// Gets the status of the hop.
        /// </summary>
        public IPStatus Status { get; init; }

        /// <summary>
        /// Gets the hostname of the hop, if resolved, or null if unavailable.
        /// </summary>
        public string? HostName { get; init; }

        /// <summary>
        /// Gets the error message if the hop failed, or null if successful.
        /// </summary>
        public string? ErrorMessage { get; init; }

        /// <summary>
        /// Returns a string representation of the traceroute hop.
        /// </summary>
        /// <returns>A formatted string describing the hop details.</returns>
        public override string ToString()
        {
            var address = HostName ?? Address?.ToString() ?? "*";
            if (Status == IPStatus.TimedOut)
            {
                return $"{Hop,2}: * Request timed out.";
            }
            if (ErrorMessage != null)
            {
                return $"{Hop,2}: {address,-30} {ErrorMessage}";
            }
            return $"{Hop,2}: {address,-30} {RoundTripTime}ms";
        }
    }

    /// <summary>
    /// Provides methods for performing ping and traceroute network diagnostics.
    /// Compatible with .NET 8.
    /// </summary>
    public class NetworkDiagnosticsService
    {
        private readonly int _defaultTimeout;
        private readonly int _maxHops;
        private readonly byte[] _buffer;

        /// <summary>
        /// Initializes a new instance of the <see cref="NetworkDiagnosticsService"/> class.
        /// </summary>
        /// <param name="timeoutMs">The timeout in milliseconds for each ping (default: 1000).</param>
        /// <param name="maxHops">The maximum number of hops for traceroute (default: 30).</param>
        /// <param name="pingSize">The size of the ping buffer in bytes (default: 32).</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if timeoutMs, maxHops, or pingSize is less than or equal to zero.</exception>
        public NetworkDiagnosticsService(int timeoutMs = 1000, int maxHops = 30, int pingSize = 32)
        {
            if (timeoutMs <= 0)
                throw new ArgumentOutOfRangeException(nameof(timeoutMs), "Timeout must be positive.");
            if (maxHops <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxHops), "Maximum hops must be positive.");
            if (pingSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(pingSize), "Ping size must be positive.");

            _defaultTimeout = timeoutMs;
            _maxHops = maxHops;
            _buffer = new byte[pingSize];
            Array.Fill(_buffer, (byte)'a'); // Initialize buffer with 'a' for consistency
        }

        /// <summary>
        /// Sends an ICMP ping to the specified host and returns the result.
        /// </summary>
        /// <param name="host">The hostname or IP address to ping.</param>
        /// <returns>A <see cref="PingResult"/> containing the ping outcome.</returns>
        /// <exception cref="ArgumentNullException">Thrown if host is null or empty.</exception>
        public async Task<PingResult> PingAsync(string host)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return new PingResult
                {
                    Host = host,
                    Status = IPStatus.BadDestination,
                    ErrorMessage = "Host cannot be empty."
                };
            }

            IPAddress? ipAddress;
            try
            {
                ipAddress = await ResolveHostAsync(host);
                if (ipAddress == null || ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.IPv6Any))
                {
                    return new PingResult
                    {
                        Host = host,
                        Status = IPStatus.BadDestination,
                        ErrorMessage = "Could not resolve host to a valid IP address."
                    };
                }
            }
            catch (SocketException ex)
            {
                return new PingResult
                {
                    Host = host,
                    Status = IPStatus.BadDestination,
                    ErrorMessage = $"DNS resolution failed: {ex.Message}"
                };
            }

            try
            {
                using var pinger = new Ping();
                var pingOptions = new PingOptions { DontFragment = true };
                var reply = await pinger.SendPingAsync(ipAddress, _defaultTimeout, _buffer, pingOptions);

                return new PingResult
                {
                    Host = host,
                    Address = reply.Address,
                    RoundTripTime = reply.RoundtripTime,
                    TimeToLive = reply.Options?.Ttl ?? 0,
                    Status = reply.Status,
                    ErrorMessage = reply.Status == IPStatus.Success ? null : $"Ping failed: {reply.Status}"
                };
            }
            catch (PingException ex)
            {
                return new PingResult
                {
                    Host = host,
                    Status = IPStatus.Unknown,
                    ErrorMessage = $"Ping error: {ex.InnerException?.Message ?? ex.Message}"
                };
            }
            catch (Exception ex)
            {
                return new PingResult
                {
                    Host = host,
                    Status = IPStatus.Unknown,
                    ErrorMessage = $"Unexpected error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Performs a traceroute to the specified host and returns the list of hops.
        /// </summary>
        /// <param name="host">The hostname or IP address to trace.</param>
        /// <returns>A list of <see cref="TracerouteHop"/> objects representing each hop.</returns>
        /// <exception cref="ArgumentNullException">Thrown if host is null or empty.</exception>
        public async Task<List<TracerouteHop>> TracerouteAsync(string host)
        {
            var hops = new List<TracerouteHop>();

            if (string.IsNullOrWhiteSpace(host))
            {
                hops.Add(new TracerouteHop
                {
                    Hop = 1,
                    Status = IPStatus.BadDestination,
                    ErrorMessage = "Host cannot be empty."
                });
                return hops;
            }

            IPAddress? ipAddress;
            try
            {
                ipAddress = await ResolveHostAsync(host);
                if (ipAddress == null || ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.IPv6Any))
                {
                    hops.Add(new TracerouteHop
                    {
                        Hop = 1,
                        Status = IPStatus.BadDestination,
                        ErrorMessage = "Could not resolve host to a valid IP address."
                    });
                    return hops;
                }
            }
            catch (SocketException ex)
            {
                hops.Add(new TracerouteHop
                {
                    Hop = 1,
                    Status = IPStatus.Unknown,
                    ErrorMessage = $"DNS resolution failed: {ex.Message}"
                });
                return hops;
            }

            try
            {
                using var pinger = new Ping();
                var pingOptions = new PingOptions { DontFragment = true };

                for (int ttl = 1; ttl <= _maxHops; ttl++)
                {
                    pingOptions.Ttl = ttl;
                    PingReply reply;

                    try
                    {
                        reply = await pinger.SendPingAsync(ipAddress, _defaultTimeout, _buffer, pingOptions);
                    }
                    catch (PingException ex)
                    {
                        hops.Add(new TracerouteHop
                        {
                            Hop = ttl,
                            Status = IPStatus.Unknown,
                            ErrorMessage = $"Ping error: {ex.InnerException?.Message ?? ex.Message}"
                        });
                        break;
                    }

                    string? hostname = await ResolveIpAddressAsync(reply.Address);

                    hops.Add(new TracerouteHop
                    {
                        Hop = ttl,
                        Address = reply.Address,
                        RoundTripTime = reply.RoundtripTime,
                        Status = reply.Status,
                        HostName = hostname,
                        ErrorMessage = reply.Status is not IPStatus.Success and not IPStatus.TtlExpired
                            ? $"Hop failed: {reply.Status}"
                            : null
                    });

                    if (reply.Status == IPStatus.Success || (reply.Status != IPStatus.TtlExpired && reply.Status != IPStatus.TimedOut))
                    {
                        break; // Stop on destination or non-recoverable error
                    }
                }
            }
            catch (Exception ex)
            {
                hops.Add(new TracerouteHop
                {
                    Hop = hops.Count + 1,
                    Status = IPStatus.Unknown,
                    ErrorMessage = $"Traceroute error: {ex.Message}"
                });
            }

            return hops;
        }

        /// <summary>
        /// Resolves a hostname to an IP address, preferring IPv4 for ICMP compatibility.
        /// </summary>
        /// <param name="host">The hostname or IP address to resolve.</param>
        /// <returns>The resolved IP address, or null if resolution fails.</returns>
        private async Task<IPAddress?> ResolveHostAsync(string host)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host);
                // Prefer IPv4 for ICMP compatibility
                foreach (var address in addresses)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return address;
                    }
                }
                return addresses.Length > 0 ? addresses[0] : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Resolves an IP address to a hostname.
        /// </summary>
        /// <param name="ipAddress">The IP address to resolve.</param>
        /// <returns>The hostname, or the IP address as a string if resolution fails or the address is invalid.</returns>
        private async Task<string?> ResolveIpAddressAsync(IPAddress? ipAddress)
        {
            if (ipAddress == null || ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.IPv6Any))
            {
                return null;
            }

            if (IPAddress.IsLoopback(ipAddress))
            {
                return "localhost";
            }

            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                return hostEntry.HostName;
            }
            catch
            {
                return ipAddress.ToString();
            }
        }
    }
}