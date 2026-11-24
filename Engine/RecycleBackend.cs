using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// =====================================================================
// 回收站后端（IFileOperation + FOFX_RECYCLEONDELETE + FOF_ALLOWUNDO）
//
// 为什么换掉 Microsoft.VisualBasic.FileIO：
//   那条路最终走 SHFileOperation，框架标志里**从不设置 FOF_WANTNUKEWARNING**，
//   拿不到“逐项同步”的回收证据，只能事后扫 $I/$R 反推。
//   IFileOperation 的 PreDeleteItem 可在 Shell 决定静默永久删除前用
//   TSF_DELETE_RECYCLE_IF_POSSIBLE 与目标强身份拦截；PostDeleteItem 会同步给出
//   psiNewlyCreated：
//     * psiNewlyCreated != NULL 且落入 \$Recycle.Bin\ ⇒ 该项确实作为新对象被创建（即进了回收站）
//     * psiNewlyCreated == NULL ⇒ 没有创建新对象
//
// ⚠ 本机实测确认的两条限制，必须随代码传递：
//   1. psiNewlyCreated == NULL **不能**单独证明永久删除 ——
//      用 PreDeleteItem 返回 ERROR_CANCELLED 取消时，PostDeleteItem 仍会回调，
//      psiNewlyCreated 也是 NULL，但文件根本没被删。
//      ⇒ 分类必须结合“源文件是否仍在”。
//   2. GetAnyOperationsAborted 在确实被取消时仍可能返回 false，
//      因此**不能**用它当“是否取消”的判据。
// =====================================================================

internal static class ShellRecycle
{
    [ComImport, Guid("3ad05575-8857-4850-9277-11b85bdb8e09")]
    internal class FileOperation { }

    [ComImport, Guid("947aab5f-0a5c-4c13-b4d6-4bf7836fc9f8"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFileOperation
    {
        [PreserveSig] int Advise([MarshalAs(UnmanagedType.Interface)] IFileOperationProgressSink pfops, out uint cookie);
        [PreserveSig] int Unadvise(uint cookie);
        [PreserveSig] int SetOperationFlags(uint flags);
        [PreserveSig] int SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string msg);
        [PreserveSig] int SetProgressDialog(IntPtr pd);
        [PreserveSig] int SetProperties(IntPtr pproparray);
        [PreserveSig] int SetOwnerWindow(IntPtr hwnd);
        [PreserveSig] int ApplyPropertiesToItem([MarshalAs(UnmanagedType.Interface)] IShellItem psi);
        [PreserveSig] int ApplyPropertiesToItems(IntPtr punkItems);
        [PreserveSig] int RenameItem([MarshalAs(UnmanagedType.Interface)] IShellItem psi, [MarshalAs(UnmanagedType.LPWStr)] string name,
                                     [MarshalAs(UnmanagedType.Interface)] IFileOperationProgressSink pfopsItem);
        [PreserveSig] int RenameItems(IntPtr punkItems, [MarshalAs(UnmanagedType.LPWStr)] string name);
        [PreserveSig] int MoveItem([MarshalAs(UnmanagedType.Interface)] IShellItem psi, [MarshalAs(UnmanagedType.Interface)] IShellItem psiDest,
                                   [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.Interface)] IFileOperationProgressSink pfopsItem);
        [PreserveSig] int MoveItems(IntPtr punkItems, [MarshalAs(UnmanagedType.Interface)] IShellItem psiDest);
        [PreserveSig] int CopyItem([MarshalAs(UnmanagedType.Interface)] IShellItem psi, [MarshalAs(UnmanagedType.Interface)] IShellItem psiDest,
                                   [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.Interface)] IFileOperationProgressSink pfopsItem);
        [PreserveSig] int CopyItems(IntPtr punkItems, [MarshalAs(UnmanagedType.Interface)] IShellItem psiDest);
        [PreserveSig] int DeleteItem([MarshalAs(UnmanagedType.Interface)] IShellItem psi,
                                     [MarshalAs(UnmanagedType.Interface)] IFileOperationProgressSink pfopsItem);
        [PreserveSig] int DeleteItems(IntPtr punkItems);
        [PreserveSig] int NewItem([MarshalAs(UnmanagedType.Interface)] IShellItem psiDest, uint attrs,
                                  [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string tmpl,
                                  [MarshalAs(UnmanagedType.Interface)] IFileOperationProgressSink pfopsItem);
        [PreserveSig] int PerformOperations();
        [PreserveSig] int GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool aborted);
    }

    [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IShellItem
    {
        [PreserveSig] int BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        [PreserveSig] int GetParent(out IShellItem parent);
        [PreserveSig] int GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string name);
        [PreserveSig] int GetAttributes(uint mask, out uint attrs);
        [PreserveSig] int Compare(IShellItem other, uint hint, out int order);
    }

    [ComImport, Guid("04b0f1a7-9490-44bc-96e1-4296a31252e2"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFileOperationProgressSink
    {
        [PreserveSig] int StartOperations();
        [PreserveSig] int FinishOperations(int hrResult);
        [PreserveSig] int PreRenameItem(uint flags, IShellItem psi, [MarshalAs(UnmanagedType.LPWStr)] string newName);
        [PreserveSig] int PostRenameItem(uint flags, IShellItem psi, [MarshalAs(UnmanagedType.LPWStr)] string newName,
                                        int hrRename, [MarshalAs(UnmanagedType.Interface)] IShellItem psiNewlyCreated);
        [PreserveSig] int PreMoveItem(uint flags, IShellItem psi, IShellItem psiDest, [MarshalAs(UnmanagedType.LPWStr)] string newName);
        [PreserveSig] int PostMoveItem(uint flags, IShellItem psi, IShellItem psiDest, [MarshalAs(UnmanagedType.LPWStr)] string newName,
                                      int hrMove, [MarshalAs(UnmanagedType.Interface)] IShellItem psiNewlyCreated);
        [PreserveSig] int PreCopyItem(uint flags, IShellItem psi, IShellItem psiDest, [MarshalAs(UnmanagedType.LPWStr)] string newName);
        [PreserveSig] int PostCopyItem(uint flags, IShellItem psi, IShellItem psiDest, [MarshalAs(UnmanagedType.LPWStr)] string newName,
                                      int hrCopy, [MarshalAs(UnmanagedType.Interface)] IShellItem psiNewlyCreated);
        [PreserveSig] int PreDeleteItem(uint flags, IShellItem psi);
        [PreserveSig] int PostDeleteItem(uint flags, IShellItem psi, int hrDelete,
                                         [MarshalAs(UnmanagedType.Interface)] IShellItem psiNewlyCreated);
        [PreserveSig] int PreNewItem(uint flags, IShellItem psiDest, [MarshalAs(UnmanagedType.LPWStr)] string newName);
        [PreserveSig] int PostNewItem(uint flags, IShellItem psiDest, [MarshalAs(UnmanagedType.LPWStr)] string newName,
                                     [MarshalAs(UnmanagedType.LPWStr)] string tmpl, uint attrs, int hrNew,
                                     [MarshalAs(UnmanagedType.Interface)] IShellItem psiNewItem);
        [PreserveSig] int UpdateProgress(uint workTotal, uint workSoFar);
        [PreserveSig] int ResetTimer();
        [PreserveSig] int PauseTimer();
        [PreserveSig] int ResumeTimer();
    }

    /// <summary>
    /// 生产标志集合（0x00180450）：
    ///   FOFX_RECYCLEONDELETE  0x00080000  —— 要求送进回收站
    ///   FOFX_EARLYFAILURE     0x00100000  —— 第一项失败即中止，不做半成品
    ///   FOF_NOERRORUI         0x00000400  —— 不显示错误弹窗
    ///   FOF_ALLOWUNDO         0x00000040  —— 显式保留可撤销回收语义（兼容全版本 Windows）
    ///   FOF_NOCONFIRMATION    0x00000010  —— 不弹确认
    /// ⚠ 刻意**不含** FOF_WANTNUKEWARNING：它是警告机制而非保证，
    ///   且在当前静默上下文中可能造成无 UI 的阻塞；静默永久删除拦截由 PreDeleteItem 强制执行。
    /// </summary>
    internal const uint FOF_NOCONFIRMATION = 0x00000010u;
    internal const uint FOF_ALLOWUNDO = 0x00000040u;
    internal const uint FOF_NOERRORUI = 0x00000400u;
    internal const uint FOFX_RECYCLEONDELETE = 0x00080000u;
    internal const uint FOFX_EARLYFAILURE = 0x00100000u;
    internal const uint Flags = FOFX_RECYCLEONDELETE | FOFX_EARLYFAILURE | FOF_NOERRORUI | FOF_ALLOWUNDO | FOF_NOCONFIRMATION;

    internal const uint TSF_DELETE_RECYCLE_IF_POSSIBLE = 0x0080u;
    internal const int HR_ERROR_CANCELLED = unchecked((int)0x800704C7);
    internal const uint SIGDN_DESKTOPABSOLUTEPARSING = 0x80028000;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    internal static extern void SHCreateItemFromParsingName(
        [MarshalAs(UnmanagedType.LPWStr)] string path, IntPtr pbc,
        [MarshalAs(UnmanagedType.LPStruct)] Guid riid,
        [MarshalAs(UnmanagedType.Interface)] out IShellItem item);

    internal static IShellItem Item(string path)
    {
        IShellItem it;
        SHCreateItemFromParsingName(path, IntPtr.Zero, typeof(IShellItem).GUID, out it);
        return it;
    }

    internal static string Display(IShellItem it)
    {
        if (it == null) return "";
        try
        {
            string s;
            return it.GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING, out s) >= 0 ? (s ?? "") : "";
        }
        catch { return ""; }
    }
}

/// <summary>
/// 一次回收调用的**实测事实**。只由 COM 回调填写，本身不做任何推断。
/// </summary>
public sealed class RecycleEvidence
{
    /// <summary>PerformOperations 的 HRESULT。</summary>
    public int HrPerform = -1;
    /// <summary>PostDeleteItem 回调里的 hrDelete。</summary>
    public int HrDelete;
    public bool PostDeleteItemFired;
    /// <summary>psiNewlyCreated != NULL —— 唯一被接受的“已回收”证据。</summary>
    public bool NewlyCreatedPresent;
    /// <summary>psiNewlyCreated 的路径（能读到才有）。</summary>
    public string RecycledTo = "";
    /// <summary>GetAnyOperationsAborted 的读数（**不可靠，仅供记录**）。</summary>
    public bool Aborted;

    public bool CancelledBeforeDispatch
    {
        get { return PostDeleteItemFired && HrDelete == ShellRecycle.HR_ERROR_CANCELLED; }
    }
}

/// <summary>
/// 进度回调：在 PreDeleteItem 强制拦住 Shell 静默永久删除与路径/身份调包；
/// 在 PostDeleteItem 严格记录回收证据。
/// </summary>
internal sealed class RecycleSink : ShellRecycle.IFileOperationProgressSink
{
    private readonly string expectedLongPath;
    private readonly FileIdentity expectedId;
    private readonly bool enforceIdentity;

    public int PostDeleteItemCount;
    public int StartCalls, FinishCalls;
    public int HrDelete;
    public bool NewlyCreatedPresent;
    public string RecycledTo = "";

    public RecycleSink(string expectedLongPath, FileIdentity expectedId, bool enforceIdentity)
    {
        this.expectedLongPath = expectedLongPath ?? "";
        this.expectedId = expectedId;
        this.enforceIdentity = enforceIdentity;
    }

    public int StartOperations() { StartCalls++; return 0; }
    public int FinishOperations(int hrResult) { FinishCalls++; return 0; }
    public int PreRenameItem(uint flags, ShellRecycle.IShellItem psi, string newName) { return 0; }
    public int PostRenameItem(uint flags, ShellRecycle.IShellItem psi, string newName, int hr, ShellRecycle.IShellItem created) { return 0; }
    public int PreMoveItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName) { return 0; }
    public int PostMoveItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName, int hr, ShellRecycle.IShellItem created) { return 0; }
    public int PreCopyItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName) { return 0; }
    public int PostCopyItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName, int hr, ShellRecycle.IShellItem created) { return 0; }

    public int PreDeleteItem(uint flags, ShellRecycle.IShellItem psi)
    {
        try
        {
            // 若 Shell 未携带 TSF_DELETE_RECYCLE_IF_POSSIBLE（0x0080），说明其准备永久删除，立即取消。
            if ((flags & ShellRecycle.TSF_DELETE_RECYCLE_IF_POSSIBLE) == 0)
                return ShellRecycle.HR_ERROR_CANCELLED;

            if (psi == null) return ShellRecycle.HR_ERROR_CANCELLED;

            string displayPath = ShellRecycle.Display(psi);
            if (String.IsNullOrEmpty(displayPath) || !PathGuard.IsLocalDrivePath(displayPath))
                return ShellRecycle.HR_ERROR_CANCELLED;
            if (PathGuard.HasAnyReparseComponent(displayPath))
                return ShellRecycle.HR_ERROR_CANCELLED;

            FileIdentity liveId;
            string liveLong;
            string why;
            if (!PermanentDeleteBin.VerifySingleFileHandle(displayPath, out liveId, out liveLong, out why))
                return ShellRecycle.HR_ERROR_CANCELLED;

            if (expectedLongPath.Length > 0
                && !String.Equals(liveLong, expectedLongPath, StringComparison.OrdinalIgnoreCase))
                return ShellRecycle.HR_ERROR_CANCELLED;

            if (enforceIdentity && (!expectedId.Ok || !liveId.SameAs(expectedId)))
                return ShellRecycle.HR_ERROR_CANCELLED;

            return 0;
        }
        catch
        {
            return ShellRecycle.HR_ERROR_CANCELLED;
        }
    }

    public int PostDeleteItem(uint flags, ShellRecycle.IShellItem psi, int hrDelete, ShellRecycle.IShellItem psiNewlyCreated)
    {
        PostDeleteItemCount++;
        if (PostDeleteItemCount == 1)
        {
            HrDelete = hrDelete;
            string recycledPath = psiNewlyCreated != null ? ShellRecycle.Display(psiNewlyCreated) : "";
            RecycledTo = recycledPath;
            NewlyCreatedPresent = (hrDelete >= 0)
                && (psiNewlyCreated != null)
                && !String.IsNullOrEmpty(recycledPath)
                && recycledPath.IndexOf("\\$Recycle.Bin\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        else
        {
            // 单文件回收绝不应触发多次 PostDeleteItem，若异常触发则保守判为无有效回收证据。
            NewlyCreatedPresent = false;
        }
        return 0;
    }

    public int PreNewItem(uint flags, ShellRecycle.IShellItem dest, string newName) { return 0; }
    public int PostNewItem(uint flags, ShellRecycle.IShellItem dest, string newName, string tmpl, uint attrs, int hrNew, ShellRecycle.IShellItem newItem) { return 0; }
    public int UpdateProgress(uint workTotal, uint workSoFar) { return 0; }
    public int ResetTimer() { return 0; }
    public int PauseTimer() { return 0; }
    public int ResumeTimer() { return 0; }
}

/// <summary>
/// 真实回收站后端：IFileOperation + FOFX_RECYCLEONDELETE + FOF_ALLOWUNDO。
/// **只处理普通文件**；目录在接口层就没有入口（不提供 SendDirectory）。
/// </summary>
public sealed class WindowsRecycleBin : IRecycleBin
{
    /// <summary>
    /// 进入 SendFile 的次数（含被闸门拦下的）。有一条测试会故意直调本类
    /// 以证明“绕过引擎也会被拦下”，所以它允许 &gt;0。
    /// </summary>
    public static int RealDispatchAttempts;

    /// <summary>
    /// **穿过闸门**的次数 —— 真正会去动文件系统的那一步。批量路径必须恒为 0。
    /// </summary>
    public static int RealGateBypasses;

    private int singleFileQuota;
    private readonly string expectedLongPath;
    private readonly FileIdentity expectedId;
    private readonly bool hasExpectedIdentity;

    public WindowsRecycleBin()
        : this(0, "", default(FileIdentity), false)
    {
    }

    private WindowsRecycleBin(int singleFileQuota, string expectedLongPath, FileIdentity expectedId, bool hasExpectedIdentity)
    {
        this.singleFileQuota = singleFileQuota;
        this.expectedLongPath = expectedLongPath ?? "";
        this.expectedId = expectedId;
        this.hasExpectedIdentity = hasExpectedIdentity;
    }

    /// <summary>
    /// 仅供 DeleteEngine.ExecuteSingleRecycle 内部调用的单文件受控实例工厂。
    /// 每次仅授权单次单个普通文件送入系统回收站（消费一次即归零，严禁用于批量自动回收），
    /// 强制走 IFileOperation + FOFX_RECYCLEONDELETE，绝不降级为永久删除。
    /// </summary>
    internal static WindowsRecycleBin CreateForSingleFile()
    {
        return new WindowsRecycleBin(1, "", default(FileIdentity), false);
    }

    internal static WindowsRecycleBin CreateForSingleFile(string expectedLongPath, FileIdentity expectedId)
    {
        return new WindowsRecycleBin(1, expectedLongPath ?? "", expectedId, expectedId.Ok);
    }

    public bool IsAvailable(string path, long bytes, bool sizeComplete, out string reason, out DeleteRefusalKind kind)
    {
        return RecycleBinProbe.IsSupported(path, bytes, sizeComplete, out reason, out kind);
    }

    public RecycleEvidence SendFile(string path)
    {
        Interlocked.Increment(ref RealDispatchAttempts);
        RecycleEvidence ev = new RecycleEvidence();
        ShellRecycle.IFileOperation op = null;
        ShellRecycle.IShellItem item = null;
        uint cookie = 0;
        bool advised = false;
        bool comCreated = false;
        try
        {
            bool authorizedSingle = Interlocked.Exchange(ref singleFileQuota, 0) == 1;
            if (!authorizedSingle)
            {
                DeleteEngine.RequireGate();     // 与旧后端同一道闸门（编译期常量派生）
                Interlocked.Increment(ref RealGateBypasses);
            }

            string canon = PathGuard.Canonical(path);
            if (canon.Length == 0
                || !PathGuard.IsLocalDrivePath(canon)
                || Directory.Exists(canon)
                || PathGuard.IsReparsePoint(canon)
                || PathGuard.HasAnyReparseComponent(canon))
            {
                ev.HrPerform = unchecked((int)0x80070057);   // E_INVALIDARG：仅接受本地非重解析普通文件路径
                return ev;
            }

            // STA 约束（产品调用层的**保守**约定）：
            // 仅在 STA 线程调用 Shell IFileOperation，拒绝非 STA 线程。
            if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
            {
                ev.HrPerform = unchecked((int)0x80010106);   // RPC_E_CHANGED_MODE
                return ev;
            }

            FileIdentity liveId;
            string liveLong;
            string handleWhy;
            if (!PermanentDeleteBin.VerifySingleFileHandle(canon, out liveId, out liveLong, out handleWhy))
            {
                ev.HrPerform = unchecked((int)0x80070057);
                return ev;
            }
            if (expectedLongPath.Length > 0
                && !String.Equals(liveLong, expectedLongPath, StringComparison.OrdinalIgnoreCase))
            {
                ev.HrPerform = ShellRecycle.HR_ERROR_CANCELLED;
                return ev;
            }
            if (hasExpectedIdentity && (!expectedId.Ok || !liveId.SameAs(expectedId)))
            {
                ev.HrPerform = ShellRecycle.HR_ERROR_CANCELLED;
                return ev;
            }

            string sinkExpectedLong = expectedLongPath.Length > 0 ? expectedLongPath : liveLong;
            FileIdentity sinkExpectedId = hasExpectedIdentity ? expectedId : liveId;

            RecycleSink sink = new RecycleSink(sinkExpectedLong, sinkExpectedId, true);
            op = (ShellRecycle.IFileOperation)new ShellRecycle.FileOperation();
            comCreated = true;

            ev.HrPerform = op.SetOperationFlags(ShellRecycle.Flags);
            if (ev.HrPerform < 0) return ev;

            ev.HrPerform = op.Advise(sink, out cookie);
            if (ev.HrPerform < 0) return ev;
            advised = true;

            item = ShellRecycle.Item(canon);
            ev.HrPerform = op.DeleteItem(item, null);
            if (ev.HrPerform < 0) return ev;

            ev.HrPerform = op.PerformOperations();

            bool aborted;
            try { op.GetAnyOperationsAborted(out aborted); ev.Aborted = aborted; } catch { }
            ev.HrDelete = sink.HrDelete;
            ev.PostDeleteItemFired = sink.PostDeleteItemCount > 0;
            ev.RecycledTo = sink.RecycledTo;
            ev.NewlyCreatedPresent = (sink.PostDeleteItemCount == 1)
                && (sink.HrDelete >= 0)
                && sink.NewlyCreatedPresent
                && !String.IsNullOrEmpty(sink.RecycledTo)
                && sink.RecycledTo.IndexOf("\\$Recycle.Bin\\", StringComparison.OrdinalIgnoreCase) >= 0;
            return ev;
        }
        finally
        {
            if (item != null)
            {
                try { Marshal.ReleaseComObject(item); } catch { }
            }
            if (op != null)
            {
                if (advised) { try { op.Unadvise(cookie); } catch { } }
                try { Marshal.ReleaseComObject(op); } catch { }
            }
            if (comCreated)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }
    }

    /// <summary>
    /// **纯函数**分类：只看实测事实，可脱离 COM 直接单测。
    ///
    /// 铁律（每条都有对应断言）：
    ///   * 不得把 HRESULT 成功当回收证据；
    ///   * 不得把“原路径消失”当回收证据；
    ///   * 只有 psiNewlyCreated != NULL **且**源已消失才叫 RecycledVerified；
    ///   * psiNewlyCreated == NULL 且源已消失 ⇒ **结果未知**（可能是永久删除，
    ///     也可能是别的情形；一律 fail-closed）；
    ///   * 源仍在 ⇒ 没有成功回收：身份一致 ⇒ FailedStillPresent（**取消就是这一支**，
    ///     绝不会被误报成永久删除）；身份不一致或读不到 ⇒ 结果未知；
    ///   * psiNewlyCreated != NULL 但源仍在 ⇒ 同样不算回收。
    /// </summary>
    public static DeleteStatus Classify(RecycleEvidence ev, bool sourceStillThere, bool identitySame)
    {
        // 先看源：源仍在就**没有**成功回收 —— 与 ev 是否为 null 无关。
        // （派发抛异常时 ev 为 null，但文件往往原地未动，那应该就是 FailedStillPresent。）
        if (sourceStillThere)
            return identitySame ? DeleteStatus.FailedStillPresent : DeleteStatus.OutcomeUnknown;

        if (ev == null) return DeleteStatus.OutcomeUnknown;

        // 源已消失：唯一被接受的证据是“回调创建了新对象”
        if (ev.PostDeleteItemFired && ev.NewlyCreatedPresent)
            return DeleteStatus.RecycledVerified;

        return DeleteStatus.OutcomeUnknown;
    }

    /// <summary>分类的说明文字（与 Classify 同源，避免两处判断不一致）。</summary>
    public static string Describe(RecycleEvidence ev, bool sourceStillThere, bool identitySame)
    {
        if (sourceStillThere)
        {
            string why = (ev != null && ev.CancelledBeforeDispatch)
                ? "（hrDelete=ERROR_CANCELLED：派发前被取消）" : "";
            // 措辞铁律：强身份一致只能证明“原位置上还是同一个对象”，
            // **不能**证明它的内容或元数据没变。只有真的重新校验过才能那么说。
            return identitySame
                ? "未回收：原位置仍是同一个对象（文件标识与扫描时一致）。"
                  + "注意：本次**没有**重新校验其内容与元数据，所以不能断言它未被修改。" + why
                : "原路径仍然存在，但**文件标识与扫描时不一致或读不到**，无法判断发生了什么，请人工核实。";
        }
        if (ev == null) return "没有取到回收证据，且原路径已消失：请立即人工核实。";
        if (ev.PostDeleteItemFired && ev.NewlyCreatedPresent)
            return "已确认进入回收站"
                 + (ev.RecycledTo.Length > 0 ? "：" + ev.RecycledTo : "")
                 + "（psiNewlyCreated != NULL）"
                 + (ev.Aborted ? "；注意 GetAnyOperationsAborted=true" : "");
        return "原路径已消失，但 **psiNewlyCreated == NULL：没有回收证据**。"
             + "无法区分它是被永久删除还是别的情形，"
             + "请立即人工核实回收站与原位置。";
    }
}
