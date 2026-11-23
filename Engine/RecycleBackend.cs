using System;
using System.Runtime.InteropServices;
using System.Text;

// =====================================================================
// 回收站后端（IFileOperation + FOFX_RECYCLEONDELETE）
//
// 为什么换掉 Microsoft.VisualBasic.FileIO：
//   那条路最终走 SHFileOperation，框架标志里**从不设置 FOF_WANTNUKEWARNING**，
//   拿不到“逐项同步”的回收证据，只能事后扫 $I/$R 反推。
//   IFileOperation 的 PostDeleteItem 会同步给出 psiNewlyCreated：
//     * psiNewlyCreated != NULL  ⇒ 该项确实作为新对象被创建（即进了回收站）
//     * psiNewlyCreated == NULL  ⇒ 没有创建新对象
//
// ⚠ 本机实测（E:\cid-host-recycle-test-18e1f068）确认的两条限制，必须随代码传递：
//   1. psiNewlyCreated == NULL **不能**单独证明永久删除 ——
//      用 PreDeleteItem 返回 ERROR_CANCELLED 取消时，PostDeleteItem 仍会回调，
//      psiNewlyCreated 也是 NULL，但文件根本没被删。
//      ⇒ 分类必须结合“源文件是否仍在”。
//   2. GetAnyOperationsAborted 在确实被取消时仍可能返回 false，
//      因此**不能**用它当“是否取消”的判据。
//
// ⚠ 仍未验证：不可回收情形（超配额 / 回收站被禁用 / 非固定卷）下
//   psiNewlyCreated 是否可靠地为 NULL。**在那之前不得声称已完成该项证明。**
//   本文件因此在“源已消失但没有回收证据”时一律返回 OutcomeUnknown，
//   绝不当作成功，也绝不当作安全。
//
// COM 声明与 vtable 顺序取自 tests/vm/ifoop.cs —— 那一套已在本机
// 经 --vtablescan（槽位 8–18 空参调用全部失败、无一个 S_OK）与真实回收实验验证过。
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
    /// 生产标志集合（与实验验证过的一致，0x00180410）：
    ///   FOFX_RECYCLEONDELETE  0x00080000  —— 要求送进回收站（在 Win8+ 隐含 FOF_ALLOWUNDO）
    ///   FOFX_EARLYFAILURE     0x00100000  —— 第一项失败即中止，不做半成品
    ///   FOF_NOERRORUI         0x00000400  —— 不显示错误弹窗
    ///   FOF_NOCONFIRMATION    0x00000010  —— 不弹确认
    /// ⚠ 刻意**不含** FOF_WANTNUKEWARNING：它是警告机制而非保证，
    ///   且在当前静默上下文中可能造成无 UI 的阻塞。这条限制已记录在案。
    /// </summary>
    internal const uint Flags = 0x00080000u | 0x00100000u | 0x00000400u | 0x00000010u;

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
            return it.GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING, out s) >= 0 ? s : "";
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
        get { return PostDeleteItemFired && HrDelete == unchecked((int)0x800704C7); }   // ERROR_CANCELLED
    }
}

/// <summary>
/// 进度回调：只**记录**事实，不做任何判断，也不吞掉操作。
/// </summary>
internal sealed class RecycleSink : ShellRecycle.IFileOperationProgressSink
{
    public int PostDeleteItemCount;
    public int StartCalls, FinishCalls;
    public int HrDelete;
    public bool NewlyCreatedPresent;
    public string RecycledTo = "";

    public int StartOperations() { StartCalls++; return 0; }
    public int FinishOperations(int hrResult) { FinishCalls++; return 0; }
    public int PreRenameItem(uint flags, ShellRecycle.IShellItem psi, string newName) { return 0; }
    public int PostRenameItem(uint flags, ShellRecycle.IShellItem psi, string newName, int hr, ShellRecycle.IShellItem created) { return 0; }
    public int PreMoveItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName) { return 0; }
    public int PostMoveItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName, int hr, ShellRecycle.IShellItem created) { return 0; }
    public int PreCopyItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName) { return 0; }
    public int PostCopyItem(uint flags, ShellRecycle.IShellItem psi, ShellRecycle.IShellItem dest, string newName, int hr, ShellRecycle.IShellItem created) { return 0; }
    public int PreDeleteItem(uint flags, ShellRecycle.IShellItem psi) { return 0; }
    public int PostDeleteItem(uint flags, ShellRecycle.IShellItem psi, int hrDelete, ShellRecycle.IShellItem psiNewlyCreated)
    {
        PostDeleteItemCount++;
        HrDelete = hrDelete;
        NewlyCreatedPresent = psiNewlyCreated != null;
        RecycledTo = NewlyCreatedPresent ? ShellRecycle.Display(psiNewlyCreated) : "";
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
/// 真实回收站后端：IFileOperation + FOFX_RECYCLEONDELETE。
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

    public WindowsRecycleBin()
    {
        this.singleFileQuota = 0;
    }

    private WindowsRecycleBin(int singleFileQuota)
    {
        this.singleFileQuota = singleFileQuota;
    }

    /// <summary>
    /// 仅供 DeleteEngine.ExecuteSingleRecycle 内部调用的单文件受控实例工厂。
    /// 每次仅授权单次单个普通文件送入系统回收站（消费一次即归零，严禁用于批量自动回收），
    /// 强制走 IFileOperation + FOFX_RECYCLEONDELETE，绝不降级为永久删除。
    /// </summary>
    internal static WindowsRecycleBin CreateForSingleFile()
    {
        return new WindowsRecycleBin(1);
    }

    public bool IsAvailable(string path, long bytes, bool sizeComplete, out string reason, out DeleteRefusalKind kind)
    {
        return RecycleBinProbe.IsSupported(path, bytes, sizeComplete, out reason, out kind);
    }

    public RecycleEvidence SendFile(string path)
    {
        RealDispatchAttempts++;
        RecycleEvidence ev = new RecycleEvidence();
        ShellRecycle.IFileOperation op = null;
        uint cookie = 0;
        bool advised = false;
        try
        {
            bool authorizedSingle = System.Threading.Interlocked.Exchange(ref singleFileQuota, 0) == 1;
            if (!authorizedSingle)
            {
                DeleteEngine.RequireGate();     // 与旧后端同一道闸门（编译期常量派生）
                RealGateBypasses++;
            }

            if (String.IsNullOrEmpty(path) || !System.IO.Path.IsPathRooted(path) || System.IO.Directory.Exists(path))
            {
                ev.HrPerform = unchecked((int)0x80070057);   // E_INVALIDARG：仅接受完整普通文件路径
                return ev;
            }

            // STA 约束（产品调用层的**保守**约定）：
            // 事实基础：本机实验工具（MTA）也能跑通 IFileOperation，
            // 所以“MTA 一定失败”并不成立。但 shell 对象的文档定位是 STA，
            // 产品实际入口（WinForms 按钮 → UI 线程，Main 上标了 [STAThread]）也是 STA。
            // 因此这里**主动**拒绝非 STA 线程：宁可拒给一个可能能跑的组合，
            // 也不要依赖“容忍但无文档保证”的行为。
            if (System.Threading.Thread.CurrentThread.GetApartmentState() != System.Threading.ApartmentState.STA)
            {
                ev.HrPerform = unchecked((int)0x80010106);   // RPC_E_CHANGED_MODE
                return ev;
            }

            RecycleSink sink = new RecycleSink();
            op = (ShellRecycle.IFileOperation)new ShellRecycle.FileOperation();

            ev.HrPerform = op.SetOperationFlags(ShellRecycle.Flags);
            if (ev.HrPerform < 0) return ev;

            ev.HrPerform = op.Advise(sink, out cookie);
            if (ev.HrPerform < 0) return ev;
            advised = true;

            ShellRecycle.IShellItem item = ShellRecycle.Item(path);
            ev.HrPerform = op.DeleteItem(item, null);
            if (ev.HrPerform < 0) return ev;

            ev.HrPerform = op.PerformOperations();

            bool aborted;
            try { op.GetAnyOperationsAborted(out aborted); ev.Aborted = aborted; } catch { }
            ev.HrDelete = sink.HrDelete;
            ev.PostDeleteItemFired = sink.PostDeleteItemCount > 0;
            ev.NewlyCreatedPresent = sink.NewlyCreatedPresent;
            ev.RecycledTo = sink.RecycledTo;
            return ev;
        }
        finally
        {
            // COM 生命周期：先注销回调，再释放，然后强制收尾。
            // （本机实验已验证这条释放路径不崩溃、引用计数归零。）
            if (op != null)
            {
                if (advised) { try { op.Unadvise(cookie); } catch { } }
                try { Marshal.ReleaseComObject(op); } catch { }
            }
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
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
    ///     也可能是别的情形；不可回收分支尚未实测，所以一律 fail-closed）；
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
             + "无法区分它是被永久删除还是别的情形（不可回收分支尚未实测），"
             + "请立即人工核实回收站与原位置。";
    }
}
