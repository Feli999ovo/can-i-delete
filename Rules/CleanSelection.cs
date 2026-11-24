using System;
using System.Collections;
using System.Collections.Generic;

// 校验前端传回的规则选择：合法规则集合与独立确认要求完全由 CacheRuleRegistry 单一真理源驱动。
public static class CleanSelection
{
    public static string Validate(Dictionary<string, object> msg, long session, out string[] rules)
    {
        rules = null;
        if (msg == null) return "清理分组无效。";
        if (session <= 0) return "扫描已变化，请重新打开清理清单。";

        object sid, kinds;
        if (!msg.TryGetValue("scanSessionId", out sid) || !(sid is int || sid is long) || Convert.ToInt64(sid) != session)
            return "扫描已变化，请重新打开清理清单。";

        if (!msg.TryGetValue("rules", out kinds) || !(kinds is IList))
            return "请选择要清理的分组。";

        IList rawList = (IList)kinds;
        CacheRuleSpec[] allSpecs = CacheRuleRegistry.All;
        if (rawList.Count == 0 || rawList.Count > allSpecs.Length)
            return "清理分组无效。";

        List<string> distinct = new List<string>(rawList.Count);
        HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < rawList.Count; i++)
        {
            object v = rawList[i];
            string ruleId = v as string;
            if (string.IsNullOrEmpty(ruleId) || !CacheRuleRegistry.IsCleanableRule(ruleId))
                return "清理分组无效。";
            if (!seen.Add(ruleId))
                return "清理分组无效。";
            distinct.Add(ruleId);
        }

        // 有界并严格校验 confirmedRules（若存在），拒绝非字符串、重复、未知规则或超长数组
        HashSet<string> confirmedSet = null;
        object confirmedObj;
        if (msg.TryGetValue("confirmedRules", out confirmedObj) && confirmedObj != null)
        {
            IList confList = confirmedObj as IList;
            if (confList == null || confList.Count > allSpecs.Length)
                return "清理分组无效。";

            confirmedSet = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < confList.Count; i++)
            {
                string item = confList[i] as string;
                if (string.IsNullOrEmpty(item) || !CacheRuleRegistry.IsCleanableRule(item))
                    return "清理分组无效。";
                if (!confirmedSet.Add(item))
                    return "清理分组无效。";
            }
        }

        for (int i = 0; i < distinct.Count; i++)
        {
            CacheRuleSpec spec = CacheRuleRegistry.Find(distinct[i]);
            if (spec == null || !spec.RequiresSeparateConfirm) continue;

            if (!HasSeparateConfirmation(msg, confirmedSet, spec.Id))
            {
                return !string.IsNullOrEmpty(spec.SeparateConfirmError)
                    ? spec.SeparateConfirmError
                    : ("请单独确认删除「" + spec.RuleLabel + "」的后果。");
            }
        }

        rules = distinct.ToArray();
        return null;
    }

    private static bool HasSeparateConfirmation(Dictionary<string, object> msg, HashSet<string> confirmedSet, string ruleId)
    {
        if (confirmedSet != null && confirmedSet.Contains(ruleId))
            return true;

        object confirmDumps;
        if (ruleId == "TMP-CRASHDUMP"
            && msg.TryGetValue("confirmDumps", out confirmDumps)
            && (confirmDumps is bool) && (bool)confirmDumps)
        {
            return true;
        }

        return false;
    }
}
