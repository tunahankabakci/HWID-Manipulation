using System;

namespace hwid_bypass;

public class ServerInterface : MarshalByRefObject
{
    private int _count;

    public void IsInstalled(int clientPid)
    {
        Console.WriteLine("Bypass has injected into process {0}.\r\n", clientPid);
    }

    public void ReportMessages(string[] messages)
    {
        foreach (var t in messages) Console.WriteLine(t);
    }

    public void ReportMessage(string message)
    {
        Console.WriteLine(message);
    }

    public void ReportException(Exception e)
    {
        Console.WriteLine("The target process has reported an error:\r\n" + e);
    }

    public void Ping()
    {
        // Output token animation to visualise Ping
        var oldTop = Console.CursorTop;
        var oldLeft = Console.CursorLeft;
        Console.CursorVisible = false;

        const string chars = "\\|/-";
        Console.SetCursorPosition(Console.WindowWidth - 1, oldTop - 1);
        Console.Write(chars[_count++ % chars.Length]);

        Console.SetCursorPosition(oldLeft, oldTop);
        Console.CursorVisible = true;
    }
}