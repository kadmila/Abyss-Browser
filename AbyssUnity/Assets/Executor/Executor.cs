using System;
using UnityEngine;

/// <summary>
/// Executor runs abyss engine. The execution order of this MonoBehaviour must be the last.
/// OnEnable, it initializes abyss_engine and writes host information to ClientUtils' static variables.
/// After OnEnable, ClientUtils is considered fully ready.
/// </summary>
public class Executor : MonoBehaviour
{
    private ClientUtils.ClientUtils clientUtils;

    private Host.Host host;
    private DateTime lastUpdate;
    private UInt64 frameCount = 0;
    private TimeSpan maxFrameCount = TimeSpan.Zero;
    private TimeSpan movingAvgFrameTime = TimeSpan.Zero;

    private void OnEnable()
    {
        clientUtils = ClientUtils.ClientUtils.GetInstance();

        try
        {
            host = new();
            host.Start();
        }
        catch (Exception e)
        {
            clientUtils.UIManager.AppendLog(e.Message);
        }
        lastUpdate = DateTime.Now;
    }
    private void OnDisable()
    {
        host.Dispose();
        host = null;

        clientUtils = null;
    }
    void Update()
    {
        DateTime time_begin = DateTime.Now;
        UpdateFrameTime(time_begin);

        //rendering calls
        while (
            (DateTime.Now - time_begin) < TimeSpan.FromMilliseconds(10) &&
            host.RenderingActionQueue.TryDequeue(out var action)
        )
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                clientUtils.UIManager.AppendLog("Fatal:::Executor failed to execute action::" + ex.ToString());
            }
        }
    }
    private void UpdateFrameTime(DateTime time_begin)
    {
        frameCount++;
        if (frameCount % 1000 == 0)
            maxFrameCount = TimeSpan.Zero;

        var delta = (time_begin - lastUpdate);
        if (delta > maxFrameCount)
            maxFrameCount = delta;
        movingAvgFrameTime = movingAvgFrameTime * 0.95 + delta * 0.05;

        clientUtils.UIManager.SetFrameTime("Frame Time (moving avg/1000-frame max): " +
            movingAvgFrameTime.TotalMilliseconds.ToString("F1") + "/" + maxFrameCount.TotalMilliseconds.ToString("F1") + " ms");
        lastUpdate = time_begin;
    }
}
