#pragma once

// Portable WeChat 4 custom-revoke-tip renderer.
// Ported from wechat-antirecall Runtime.mm (macOS). No Windows headers.

#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace revoke_tip {

constexpr size_t kMaxPhraseCodePoints = 120;
constexpr size_t kMaxContentCache = 100000;
constexpr size_t kMaxReceiveCache = 2048;
constexpr size_t kMaxTimeCache = 512;
constexpr size_t kMaxContentPreviewBytes = 240;
constexpr const char *kDefaultPhrase = "已拦截 {from} 于 {time} 撤回：{content}";

inline size_t utf8CodePoints(const std::string &value)
{
    size_t count = 0;
    for (unsigned char byte : value)
    {
        if ((byte & 0xC0) != 0x80)
            count += 1;
    }
    return count;
}

inline std::string trimCopy(const std::string &value)
{
    const char *whitespace = " \t\r\n\"'";
    const auto start = value.find_first_not_of(whitespace);
    if (start == std::string::npos)
        return "";
    const auto end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

inline void replaceAll(std::string &value, const std::string &needle, const std::string &replacement)
{
    if (needle.empty())
        return;
    size_t position = 0;
    while ((position = value.find(needle, position)) != std::string::npos)
    {
        value.replace(position, needle.length(), replacement);
        position += replacement.length();
    }
}

inline bool hasPrefix(const std::string &value, const std::string &prefix)
{
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

inline bool hasSuffix(const std::string &value, const std::string &suffix)
{
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline bool isValidPhrase(const std::string &phrase, std::string *error = nullptr)
{
    const auto trimmed = trimCopy(phrase);
    if (trimmed.empty())
    {
        if (error)
            *error = "撤回提示短语不能为空";
        return false;
    }
    if (trimmed.find('\n') != std::string::npos || trimmed.find('\r') != std::string::npos)
    {
        if (error)
            *error = "短语不能包含换行";
        return false;
    }
    if (trimmed.find("]]>") != std::string::npos)
    {
        if (error)
            *error = "撤回提示短语不能包含 CDATA 结束标记";
        return false;
    }
    if (utf8CodePoints(trimmed) > kMaxPhraseCodePoints)
    {
        if (error)
            *error = "短语过长";
        return false;
    }
    return true;
}

inline std::string sanitizedPhrase(const std::string &phrase)
{
    const auto trimmed = trimCopy(phrase);
    return isValidPhrase(trimmed) ? trimmed : std::string(kDefaultPhrase);
}

inline std::string extractSenderName(const std::string &originalTip)
{
    const std::string chineseMarker = "撤回";
    auto position = originalTip.find(chineseMarker);
    if (position != std::string::npos)
        return trimCopy(originalTip.substr(0, position));

    const std::string englishMarker = " recalled ";
    position = originalTip.find(englishMarker);
    if (position != std::string::npos)
    {
        auto sender = trimCopy(originalTip.substr(0, position));
        if (sender == "You")
            return "";
        return sender;
    }
    return "";
}

inline bool looksLikeKnownRenderedTip(const std::string &tip)
{
    return hasPrefix(tip, "已拦截") && tip.find("撤回") != std::string::npos;
}

inline bool tipIndicatesSelfRecall(const std::string &tip)
{
    if (tip.empty())
        return false;
    static const char *const selfMarkers[] = {
        "You recalled ",
        "你撤回",
        "你收回",
        "你回收",
    };
    for (const char *marker : selfMarkers)
    {
        if (tip.find(marker) != std::string::npos)
            return true;
    }
    return false;
}

inline const std::vector<std::string> &placeholders()
{
    static const std::vector<std::string> values = {"{from}", "{time}", "{content}"};
    return values;
}

inline std::vector<std::string> literalPartsForTemplate(const std::string &configuredPhrase)
{
    std::vector<std::string> parts;
    size_t cursor = 0;
    while (true)
    {
        size_t nextPosition = std::string::npos;
        size_t nextLength = 0;
        for (const auto &placeholder : placeholders())
        {
            const auto position = configuredPhrase.find(placeholder, cursor);
            if (position != std::string::npos &&
                (nextPosition == std::string::npos || position < nextPosition))
            {
                nextPosition = position;
                nextLength = placeholder.size();
            }
        }
        if (nextPosition == std::string::npos)
        {
            parts.push_back(configuredPhrase.substr(cursor));
            return parts;
        }
        parts.push_back(configuredPhrase.substr(cursor, nextPosition - cursor));
        cursor = nextPosition + nextLength;
    }
}

inline bool matchesRenderedTemplate(const std::string &tip, const std::string &configuredPhrase)
{
    const auto parts = literalPartsForTemplate(configuredPhrase);
    if (parts.size() <= 1)
        return tip == configuredPhrase;
    if (!parts.front().empty() && !hasPrefix(tip, parts.front()))
        return false;
    if (!parts.back().empty() && !hasSuffix(tip, parts.back()))
        return false;

    size_t cursor = parts.front().empty() ? 0 : parts.front().size();
    for (size_t index = 1; index < parts.size(); index += 1)
    {
        const auto &part = parts[index];
        if (part.empty())
            continue;
        const auto position = tip.find(part, cursor);
        if (position == std::string::npos)
            return false;
        cursor = position + part.size();
    }
    return true;
}

inline bool isDigit(char character)
{
    return character >= '0' && character <= '9';
}

inline bool isClockTextAt(const std::string &value, size_t position)
{
    return position + 5 <= value.size() &&
           isDigit(value[position]) &&
           isDigit(value[position + 1]) &&
           value[position + 2] == ':' &&
           isDigit(value[position + 3]) &&
           isDigit(value[position + 4]);
}

inline size_t findTimeMarker(const std::string &value, size_t cursor)
{
    const std::string marker = " 于 ";
    while (true)
    {
        const auto position = value.find(marker, cursor);
        if (position == std::string::npos)
            return std::string::npos;
        if (isClockTextAt(value, position + marker.size()))
            return position;
        cursor = position + marker.size();
    }
}

inline std::string collapseDuplicateTimeMarkers(std::string value)
{
    const std::string marker = " 于 ";
    size_t cursor = 0;
    while (true)
    {
        const auto first = findTimeMarker(value, cursor);
        if (first == std::string::npos)
            return value;
        const auto firstEnd = first + marker.size() + 5;
        const auto second = findTimeMarker(value, firstEnd);
        const auto revoke = value.find(" 撤回", firstEnd);
        if (second != std::string::npos && (revoke == std::string::npos || second < revoke))
        {
            value.erase(second, marker.size() + 5);
            cursor = firstEnd;
            continue;
        }
        cursor = firstEnd;
    }
}

inline std::string normalizeRenderedTip(const std::string &tip, const std::string &configuredPhrase)
{
    auto normalized = tip;
    const auto parts = literalPartsForTemplate(configuredPhrase);
    if (parts.size() <= 1 || parts.front().empty())
        return collapseDuplicateTimeMarkers(normalized);

    const auto &prefix = parts.front();
    while (hasPrefix(normalized, prefix + prefix))
    {
        auto candidate = normalized.substr(prefix.size());
        if (!matchesRenderedTemplate(candidate, configuredPhrase))
            break;
        normalized = candidate;
    }
    return collapseDuplicateTimeMarkers(normalized);
}

inline std::string currentTimeText()
{
    std::time_t now = std::time(nullptr);
    std::tm tm_buf {};
#if defined(_WIN32) && defined(_MSC_VER)
    localtime_s(&tm_buf, &now);
#else
    std::tm *parsed = std::localtime(&now);
    if (parsed != nullptr)
        tm_buf = *parsed;
#endif
    char buf[8] = {};
    std::strftime(buf, sizeof(buf), "%H:%M", &tm_buf);
    return buf;
}

inline bool parseUnsignedInteger(const std::string &value, uint64_t &result)
{
    const auto trimmed = trimCopy(value);
    if (trimmed.empty())
        return false;
    uint64_t parsed = 0;
    for (const char character : trimmed)
    {
        if (character < '0' || character > '9')
            return false;
        const uint64_t digit = static_cast<uint64_t>(character - '0');
        if (parsed > (UINT64_MAX - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    result = parsed;
    return true;
}

inline std::string xmlTagValue(const std::string &xml, const std::string &tagName)
{
    const auto startTag = "<" + tagName + ">";
    const auto endTag = "</" + tagName + ">";
    const auto start = xml.find(startTag);
    if (start == std::string::npos)
        return "";
    const auto valueStart = start + startTag.size();
    const auto end = xml.find(endTag, valueStart);
    if (end == std::string::npos)
        return "";
    return xml.substr(valueStart, end - valueStart);
}

inline std::string stripCdata(const std::string &value)
{
    const std::string open = "<![CDATA[";
    const std::string close = "]]>";
    if (hasPrefix(value, open) && hasSuffix(value, close) && value.size() >= open.size() + close.size())
        return value.substr(open.size(), value.size() - open.size() - close.size());
    return value;
}

inline bool looksLikeRevokeXml(const std::string &payload)
{
    return payload.find("<revokemsg") != std::string::npos ||
           payload.find("<sysmsg") != std::string::npos;
}

inline std::string displayTipFromPayload(const std::string &payload)
{
    const auto replaceMsg = xmlTagValue(payload, "replacemsg");
    if (!replaceMsg.empty())
        return stripCdata(replaceMsg);
    // WeChat 4.1.9 Windows stores the visible tip in <content>, not <replacemsg>.
    if (looksLikeRevokeXml(payload))
    {
        const auto content = xmlTagValue(payload, "content");
        if (!content.empty())
            return stripCdata(content);
    }
    if (hasPrefix(trimCopy(payload), "<?xml") || hasPrefix(trimCopy(payload), "<sysmsg") ||
        hasPrefix(trimCopy(payload), "<revokemsg"))
        return "";
    return payload;
}

inline std::string formatUnixTimestamp(uint64_t timestamp)
{
    if (timestamp > 10000000000ULL)
        timestamp /= 1000;
    std::time_t value = static_cast<std::time_t>(timestamp);
    std::tm tm_buf {};
#if defined(_WIN32) && defined(_MSC_VER)
    localtime_s(&tm_buf, &value);
#else
    std::tm *parsed = std::localtime(&value);
    if (parsed != nullptr)
        tm_buf = *parsed;
#endif
    char buf[8] = {};
    std::strftime(buf, sizeof(buf), "%H:%M", &tm_buf);
    return buf;
}

inline std::string timeTextFromXml(const std::string &xml)
{
    if (xml.empty())
        return "";
    static const char *const timeTags[] = {"createtime", "createTime", "CreateTime", "time"};
    for (const char *tag : timeTags)
    {
        uint64_t timestamp = 0;
        if (parseUnsignedInteger(xmlTagValue(xml, tag), timestamp) && timestamp != 0)
            return formatUnixTimestamp(timestamp);
    }
    return "";
}

inline uint64_t newMsgIdFromXml(const std::string &xml)
{
    if (xml.empty())
        return 0;
    static const char *const idTags[] = {"newmsgid", "newMsgId", "NewMsgId", "newmsgId"};
    for (const char *tag : idTags)
    {
        uint64_t value = 0;
        if (parseUnsignedInteger(xmlTagValue(xml, tag), value) && value != 0)
            return value;
    }
    return 0;
}

inline std::string sessionFromXml(const std::string &xml)
{
    auto session = xmlTagValue(xml, "session");
    return trimCopy(session);
}

inline std::string truncateUtf8(const std::string &value, size_t maxBytes)
{
    if (value.size() <= maxBytes)
        return value;
    size_t end = maxBytes;
    while (end > 0 && (static_cast<unsigned char>(value[end]) & 0xC0) == 0x80)
        end -= 1;
    return value.substr(0, end) + "\xE2\x80\xA6";
}

inline std::string messageKindPlaceholder(uint32_t contentMsgType)
{
    switch (contentMsgType)
    {
    case 1:
        return "";
    case 3:
        return "[图片]";
    case 34:
        return "[语音]";
    case 43:
    case 62:
        return "[视频]";
    case 42:
        return "[名片]";
    case 47:
        return "[动画表情]";
    case 48:
        return "[位置]";
    case 49:
        return "[链接]";
    case 50:
        return "[音视频通话]";
    case 10000:
    case 10002:
        return "[系统消息]";
    default:
        return "[消息]";
    }
}

inline uint32_t guessMsgTypeFromXml(const std::string &raw)
{
    if (raw.find("<revokemsg") != std::string::npos)
        return 10002;
    if (raw.find("<img") != std::string::npos || raw.find("<imgmsg") != std::string::npos)
        return 3;
    if (raw.find("voicemsg") != std::string::npos)
        return 34;
    if (raw.find("videomsg") != std::string::npos)
        return 43;
    if (raw.find("<emoji") != std::string::npos)
        return 47;
    if (raw.find("<location") != std::string::npos)
        return 48;
    if (raw.find("<appmsg") != std::string::npos)
        return 49;
    if (raw.find("<voip") != std::string::npos)
        return 50;
    return 0;
}

inline std::string contentPreviewForReceivedMessage(uint32_t contentMsgType, const std::string &rawContent)
{
    uint32_t type = contentMsgType;
    if (type == 0 || type == 1)
    {
        const auto guessed = guessMsgTypeFromXml(rawContent);
        if (guessed != 0)
            type = guessed;
    }
    if (type == 1 || type == 0)
        return truncateUtf8(trimCopy(rawContent), kMaxContentPreviewBytes);
    const auto placeholder = messageKindPlaceholder(type);
    return placeholder.empty() ? truncateUtf8(trimCopy(rawContent), kMaxContentPreviewBytes) : placeholder;
}

inline void replaceTimePlaceholder(std::string &rendered, const std::string &timeText)
{
    if (!timeText.empty())
    {
        replaceAll(rendered, "{time}", timeText);
        return;
    }
    static const char *const emptyTimePatterns[] = {
        " 于 {time}",
        " 于{time}",
        "于 {time}",
        "于{time}",
    };
    for (const char *pattern : emptyTimePatterns)
    {
        const auto position = rendered.find(pattern);
        if (position != std::string::npos)
        {
            rendered.erase(position, std::char_traits<char>::length(pattern));
            break;
        }
    }
    replaceAll(rendered, "{time}", "");
}

inline void replaceContentPlaceholder(std::string &rendered, const std::string &contentText)
{
    if (!contentText.empty())
    {
        replaceAll(rendered, "{content}", contentText);
        return;
    }
    static const char *const emptyContentPatterns[] = {
        "：{content}",
        ": {content}",
        ":{content}",
        " {content}",
    };
    for (const char *pattern : emptyContentPatterns)
    {
        const auto position = rendered.find(pattern);
        if (position != std::string::npos)
        {
            rendered.erase(position, std::char_traits<char>::length(pattern));
            break;
        }
    }
    replaceAll(rendered, "{content}", "");
}

inline std::string render(
    const std::string &originalTip,
    const std::string &configuredPhrase,
    const std::string &timeText,
    const std::string &contentPreview)
{
    if (configuredPhrase.empty())
        return originalTip;
    if (tipIndicatesSelfRecall(originalTip))
        return originalTip;
    if (matchesRenderedTemplate(originalTip, configuredPhrase))
        return normalizeRenderedTip(originalTip, configuredPhrase);
    if (looksLikeKnownRenderedTip(originalTip))
        return collapseDuplicateTimeMarkers(originalTip);

    auto rendered = configuredPhrase;
    replaceAll(rendered, "{from}", extractSenderName(originalTip));
    replaceTimePlaceholder(rendered, timeText);
    replaceContentPlaceholder(rendered, contentPreview);
    return rendered;
}

inline std::mutex &timeCacheMutex()
{
    static std::mutex mutex;
    return mutex;
}

inline std::unordered_map<std::string, std::string> &timeCache()
{
    static std::unordered_map<std::string, std::string> cache;
    return cache;
}

inline std::string timeCacheKey(uint64_t newMsgId, const std::string &xml, const std::string &originalTip)
{
    if (newMsgId != 0)
        return "id:" + std::to_string(newMsgId);
    if (!xml.empty())
        return "xml:" + std::to_string(std::hash<std::string>{}(xml));
    return "tip:" + std::to_string(std::hash<std::string>{}(originalTip));
}

inline std::string stableTimeText(
    uint64_t newMsgId,
    const std::string &xml,
    const std::string &originalTip,
    const std::string &fallbackTime)
{
    const auto xmlTime = timeTextFromXml(xml);
    if (!xmlTime.empty())
        return xmlTime;

    const auto key = timeCacheKey(newMsgId, xml, originalTip);
    std::lock_guard<std::mutex> lock(timeCacheMutex());
    auto &cache = timeCache();
    const auto found = cache.find(key);
    if (found != cache.end())
        return found->second;
    if (cache.size() >= kMaxTimeCache)
        cache.clear();
    cache[key] = fallbackTime;
    return fallbackTime;
}

inline std::mutex &contentCacheMutex()
{
    static std::mutex mutex;
    return mutex;
}

inline std::unordered_map<uint64_t, std::string> &contentCache()
{
    static std::unordered_map<uint64_t, std::string> cache;
    return cache;
}

inline void rememberContent(uint64_t newMsgId, const std::string &preview)
{
    if (newMsgId == 0 || preview.empty())
        return;
    std::lock_guard<std::mutex> lock(contentCacheMutex());
    auto &cache = contentCache();
    if (cache.size() >= kMaxContentCache)
        cache.clear();
    cache[newMsgId] = preview;
}

inline bool tryLookupContent(uint64_t newMsgId, std::string &out)
{
    if (newMsgId == 0)
        return false;
    std::unique_lock<std::mutex> lock(contentCacheMutex(), std::try_to_lock);
    if (!lock.owns_lock())
        return false;
    const auto found = contentCache().find(newMsgId);
    if (found == contentCache().end())
        return false;
    out = found->second;
    return true;
}

inline bool lookupContent(uint64_t newMsgId, std::string &out)
{
    if (newMsgId == 0)
        return false;
    std::lock_guard<std::mutex> lock(contentCacheMutex());
    const auto found = contentCache().find(newMsgId);
    if (found == contentCache().end())
        return false;
    out = found->second;
    return true;
}

inline void clearContentCache()
{
    std::lock_guard<std::mutex> lock(contentCacheMutex());
    contentCache().clear();
}

inline void clearTimeCache()
{
    std::lock_guard<std::mutex> lock(timeCacheMutex());
    timeCache().clear();
}

inline std::string renderForEvent(
    const std::string &originalTip,
    const std::string &configuredPhrase,
    uint64_t newMsgId,
    const std::string &xml,
    const std::string &fallbackTime,
    const std::string &contentPreview)
{
    const auto timeText = stableTimeText(newMsgId, xml, originalTip, fallbackTime);
    return render(originalTip, configuredPhrase, timeText, contentPreview);
}

inline std::string xmlEscape(const std::string &value)
{
    std::string out;
    out.reserve(value.size());
    for (char character : value)
    {
        switch (character)
        {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        default: out += character; break;
        }
    }
    return out;
}

inline bool replaceTagInner(std::string &payload, const std::string &open, const std::string &close, const std::string &inner)
{
    auto start = payload.find(open);
    if (start == std::string::npos)
        return false;
    auto innerStart = start + open.size();
    auto end = payload.find(close, innerStart);
    if (end == std::string::npos)
        return false;
    payload.replace(innerStart, end - innerStart, inner);
    return true;
}

inline std::string applyTipToPayload(const std::string &payload, const std::string &tip)
{
    auto next = payload;
    if (replaceTagInner(next, "<replacemsg><![CDATA[", "]]></replacemsg>", tip) ||
        replaceTagInner(next, "<replacemsg>", "</replacemsg>", xmlEscape(tip)) ||
        replaceTagInner(next, "<content><![CDATA[", "]]></content>", tip) ||
        replaceTagInner(next, "<content>", "</content>", xmlEscape(tip)))
        return next;
    if (looksLikeRevokeXml(payload))
        return payload;
    return tip;
}

inline std::string compactRevokeXml(const std::string &tip)
{
    // Keep the tags WeChat 4 actually parses. Dropping xml/revoketime shows
    // "暂不支持该内容，请在手机上查看".
    return "<?xml version=\"1.0\"?><sysmsg type=\"revokemsg\"><revokemsg><content>" +
           xmlEscape(tip) + "</content><revoketime>0</revoketime></revokemsg></sysmsg>";
}

inline std::string squeezeTip(std::string tip)
{
    replaceAll(tip, "：", ":");
    replaceAll(tip, " 于 ", "于");
    replaceAll(tip, " 撤回", "撤回");
    replaceAll(tip, "  ", " ");
    return tip;
}

inline std::string fitTipToCapacity(const std::string &payload, const std::string &tip, size_t capacity)
{
    auto patched = applyTipToPayload(payload, tip);
    if (patched.size() <= capacity)
        return patched;

    auto squeezed = squeezeTip(tip);
    patched = applyTipToPayload(payload, squeezed);
    if (patched.size() <= capacity)
        return patched;

    auto compact = compactRevokeXml(squeezed);
    if (compact.size() <= capacity)
        return compact;
    compact = compactRevokeXml(tip);
    if (compact.size() <= capacity)
        return compact;

    std::string t = squeezed;
    while (t.size() > 8)
    {
        t = truncateUtf8(t, t.size() - 8);
        patched = applyTipToPayload(payload, t);
        if (patched.size() <= capacity)
            return patched;
        compact = compactRevokeXml(t);
        if (compact.size() <= capacity)
            return compact;
    }
    return truncateUtf8(squeezed, capacity);
}

inline std::string fitUtf8(const std::string &value, size_t capacity)
{
    if (value.size() <= capacity)
        return value;
    if (capacity == 0)
        return "";
    return truncateUtf8(value, capacity);
}

inline bool looksLikeWxId(const std::string &value)
{
    if (hasPrefix(value, "wxid_") || hasPrefix(value, "gh_") || hasPrefix(value, "fmessage"))
        return true;
    if (value.find("@chatroom") != std::string::npos)
        return true;
    if (value == "filehelper" || value == "newsapp" || value == "weixin")
        return true;
    return false;
}

inline bool looksLikeMsgSource(const std::string &value)
{
    return value.find("<msgsource") != std::string::npos ||
           value.find("<bizflag") != std::string::npos ||
           value.find("<membercount") != std::string::npos ||
           value.find("<tmp_node") != std::string::npos ||
           (value.find("<pua>") != std::string::npos && value.find("<signature>") != std::string::npos);
}

inline bool looksLikeRevokePayload(const std::string &value)
{
    return value.find("<revokemsg") != std::string::npos ||
           value.find("撤回") != std::string::npos ||
           value.find("recalled") != std::string::npos;
}

} // namespace revoke_tip
