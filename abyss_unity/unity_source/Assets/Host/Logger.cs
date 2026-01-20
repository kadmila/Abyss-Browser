using System.IO;
using UnityEngine;

public class FileLogger : MonoBehaviour
{
    private StreamWriter logWriter;
    private string logFilePath;

    void Start()
    {
        // Get the directory of the executable
        string exeDirectory = Directory.GetParent(Application.dataPath).FullName;

        // Define the log file path in the same directory as the executable
        logFilePath = Path.Combine(exeDirectory, "game_log.txt");

        // Open the file for writing
        logWriter = new StreamWriter(logFilePath); // 'true' to append to the file if it exists
        logWriter.AutoFlush = true; // Auto flush so data is written immediately to the file

        // Subscribe to the log message event
        Application.logMessageReceived += LogToFile;
    }

    // This will be called whenever a log message is generated
    private void LogToFile(string logString, string stackTrace, LogType type)
    {
        string logEntry = $"{System.DateTime.Now}: [{type}] {logString}\n";

        if (type == LogType.Exception || type == LogType.Error)
        {
            logEntry += $"{stackTrace}\n";
        }

        // Write the log entry to the file
        logWriter.WriteLine(logEntry);
    }

    // Unsubscribe and close the log file when the object is destroyed
    void OnDestroy()
    {
        Application.logMessageReceived -= LogToFile;

        // Close the file when the application quits or object is destroyed
        if (logWriter != null)
        {
            logWriter.Close();
            logWriter = null;
        }
    }
}
