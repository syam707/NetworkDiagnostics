using NetworkDiagnostics;

/// <summary>
/// Contains an example Main method to demonstrate usage of the NetworkDiagnosticsService.
/// </summary>
public class Program
{
    public static async Task Main(string[] args)
    {
        var diagnosticsService = new NetworkDiagnosticsService();

        Console.WriteLine("--- Testing Ping Service ---");
        string target1 = "8.8.8.8"; // Google DNS
        Console.WriteLine($"Pinging {target1}...");
        var pingResult1 = await diagnosticsService.PingAsync(target1);
        Console.WriteLine(pingResult1);
        Console.WriteLine();

        string target2 = "google.com";
        Console.WriteLine($"Pinging {target2}...");
        var pingResult2 = await diagnosticsService.PingAsync(target2);
        Console.WriteLine(pingResult2);
        Console.WriteLine();


        Console.WriteLine("--- Testing Traceroute Service ---");
        string tracerouteTarget = "google.com";
        Console.WriteLine($"Tracing route to {tracerouteTarget}...");

        var hops = await diagnosticsService.TracerouteAsync(tracerouteTarget);
        foreach (var hop in hops)
        {
            Console.WriteLine(hop);
        }

        Console.WriteLine("\nTrace complete.");
    }
} 