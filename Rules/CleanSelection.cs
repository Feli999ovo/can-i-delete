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
            if (seen.Add(ruleId))
                distinct.Add(ruleId);
        }

        rules = distinct.ToArray();

        for (int i = 0; i < rules.Length; i++)
        {
            CacheRuleSpec spec = CacheRuleRegistry.Find(rules[i]);
            if (spec == null || !spec.RequiresSeparateConfirm) continue;

            if (!HasSeparateConfirmation(msg, spec.Id))
            {
                return !string.IsNullOrEmpty(spec.SeparateConfirmError)
                    ? spec.SeparateConfirmError
                    : ("请单独确认删除「" + spec.RuleLabel + "」的后果。");
            }
        }

        return null;
    }

    private static bool HasSeparateConfirmation(Dictionary<string, object> msg, string ruleId)
    {
        object confirmDumps;
        if (ruleId == "TMP-CRASHDUMP"
            && msg.TryGetValue("confirmDumps", out confirmDumps)
            && (confirmDumps is bool) && (bool)confirmDumps)
        {
            return true;
        }

        object confirmedRules;
        if (msg.TryGetValue("confirmedRules", out confirmedRules) && confirmedRules is IList)
        {
            IList list = (IList)confirmedRules;
            for (int i = 0; i < list.Count; i++)
            {
                string item = list[i] as string;
                if (string.Equals(item, ruleId, StringComparison.Ordinal))
                    return true;
            }
        }

        return false;
    }
}
