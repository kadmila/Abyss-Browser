using System;
using UnityEngine;

/// <summary>
/// Executor runs abyss engine. This script must execute after RenderBase and UIBase.
/// Static classes that are referenced globally should be initialized and cleared in this monobehavior.
/// </summary>
#nullable enable
public class Executor : MonoBehaviour
{
    public GlobalDependency.RendererBase RendererBase;
    public GlobalDependency.UIBase UIBase;
    public GlobalDependency.InteractionBase InteractionBase;
    public GlobalDependency.CommonShaderLoader ShaderLoader;

    private Host.Host? _host;
    private DateTime _last_update;
    private UInt64 _frame_count = 0;
    private TimeSpan _max_frame_time = TimeSpan.Zero;
    private TimeSpan _moving_avg_frame_time = TimeSpan.Zero;

    void OnEnable()
    {
        GlobalDependency.RuntimeCout.Set(UIBase.AppendConsole);
        GlobalDependency.UnityThreadChecker.Init();
        GlobalDependency.Statics.ShaderLoader = ShaderLoader;
        GlobalDependency.Logger.Init();

        _host = new(RendererBase, UIBase, InteractionBase);
        _host.Init();
        _host.Start();
        _last_update = DateTime.Now;
    }
    void Update()
    {
        _frame_count++;
        if (_frame_count % 1000 == 0)
            _max_frame_time = TimeSpan.Zero;
        DateTime time_begin = DateTime.Now; // Current time
        var delta = (time_begin - _last_update);
        if (delta > _max_frame_time)
            _max_frame_time = delta;
        _moving_avg_frame_time = _moving_avg_frame_time * 0.95 + delta * 0.05;

        UIBase.SetFrameTime("Frame Time (moving avg/1000-frame max): " +
            _moving_avg_frame_time.TotalMilliseconds.ToString("F1") + "/" + _max_frame_time.TotalMilliseconds.ToString("F1") + " ms");
        _last_update = time_begin;

        while (_host!.RenderingActionQueue.TryDequeue(out var action))
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                GlobalDependency.RuntimeCout.Print("Fatal:::Executor failed to execute action::" + ex.ToString());
            }

            if ((DateTime.Now - time_begin) > TimeSpan.FromMilliseconds(10))
                break;
        }
        while (_host.StderrQueue.TryDequeue(out var err_msg))
        {
            GlobalDependency.RuntimeCout.Print("Engine:::StdErr>> " + err_msg);

            if ((DateTime.Now - time_begin) > TimeSpan.FromMilliseconds(16))
                break;
        }
    }
    void OnDisable()
    {
        _host?.Dispose();
        _host = null;

        GlobalDependency.Logger.Clear();
        GlobalDependency.Statics.Clear();
        GlobalDependency.UnityThreadChecker.Clear();
        GlobalDependency.RuntimeCout.Clear();
    }
}
